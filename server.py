"""Digital Signature Hash Video Platform.

This single-file Flask application uses Ed25519 public keys as identities and
SHA-256 hashes as video addresses. The browser signs a canonical manifest that
contains every individual video hash, a revision chain, a timezone-aware signed
time, a user-selected expiration time, and an automatic signed note. The server
verifies the signature before accepting uploads, stores identical video bytes
only once, atomically replaces the current manifest for the public key, verifies
stored objects before download, and restores a useful video extension such as
.mp4, .webm, or .mkv when the format can be identified.
"""

# SPDX-License-Identifier: AGPL-3.0-or-later

# -----------------------------------------------------------------------------
# Standard-library and third-party imports
# -----------------------------------------------------------------------------

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import RLock
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from flask import Flask, Response, g, jsonify, render_template_string, request, send_file
from werkzeug.exceptions import RequestEntityTooLarge

import base64
import binascii
import hashlib
import json
import mimetypes
import os
import re
import secrets
import sqlite3
import tempfile

# -----------------------------------------------------------------------------
# Paths and runtime configuration
# -----------------------------------------------------------------------------

BASE_DIRECTORY = Path(__file__).resolve().parent  # Directory containing this single-file application.
DATABASE_PATH = Path(os.environ.get("DATABASE_PATH", BASE_DIRECTORY / "digital_signature_hash_video_platform.db"))  # SQLite database location.
OBJECT_DIRECTORY = Path(os.environ.get("OBJECT_DIRECTORY", BASE_DIRECTORY / "video_objects"))  # Content-addressed video object directory.
TEMPORARY_DIRECTORY = Path(os.environ.get("TEMPORARY_DIRECTORY", BASE_DIRECTORY / "temporary_uploads"))  # Temporary upload staging directory.
MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", 32 * 1024 * 1024 * 1024))  # Maximum size of one HTTP upload request.
MAX_MANIFEST_FILES = max(1, int(os.environ.get("MAX_MANIFEST_FILES", "10000")))  # Maximum unique hashes in one signed manifest.
PENDING_LIFETIME_MINUTES = max(5, int(os.environ.get("PENDING_LIFETIME_MINUTES", "120")))  # Lifetime of a verified two-phase publication token.
VERIFY_OBJECTS_ON_SEARCH = os.environ.get("VERIFY_OBJECTS_ON_SEARCH", "1") == "1"  # Rehash stored objects before returning search status.
INTEGRITY_WORKERS = max(1, int(os.environ.get("INTEGRITY_WORKERS", min(4, os.cpu_count() or 1))))  # Parallel workers used for integrity checks.
DEVELOPMENT_HOST = os.environ.get("HOST", "0.0.0.0")  # Development server bind address.
DEVELOPMENT_PORT = int(os.environ.get("PORT", "5000"))  # Development server TCP port.
DEVELOPMENT_TLS = os.environ.get("DEVELOPMENT_TLS", "adhoc").strip().lower()  # Use ad-hoc HTTPS when set to "adhoc".
SOURCE_CODE_URL = "https://github.com/wangyifan349/digital-signature-hash-video-platform"  # AGPL source repository.

# -----------------------------------------------------------------------------
# Protocol constants and validation patterns
# -----------------------------------------------------------------------------

PUBLIC_KEY_PREFIX = "ed25519:"  # Prefix for a Base64URL-encoded 32-byte Ed25519 public key.
HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")  # Canonical lowercase SHA-256 hexadecimal form.
PUBLIC_KEY_PATTERN = re.compile(r"^ed25519:([A-Za-z0-9_-]{43})$")  # Canonical unpadded Base64URL public-key form.
SIGNATURE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{86}$")  # Canonical unpadded Base64URL Ed25519 signature form.
OBJECT_STORAGE_LOCK = RLock()  # Serializes final object replacement and metadata updates.

OBJECT_DIRECTORY.mkdir(parents=True, exist_ok=True)  # Ensure persistent object storage exists.
TEMPORARY_DIRECTORY.mkdir(parents=True, exist_ok=True)  # Ensure temporary upload storage exists.

# -----------------------------------------------------------------------------
# Flask application and pinned browser dependencies
# -----------------------------------------------------------------------------

application = Flask(__name__)  # Primary Flask/WSGI application object.
application.config.update(MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES, SEND_FILE_MAX_AGE_DEFAULT=31536000)  # Apply upload and immutable-cache limits.
app = application  # Conventional WSGI alias for deployment tools.

BOOTSTRAP_CSS_URL = "https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css"  # Pinned Bootstrap stylesheet.
BOOTSTRAP_JS_URL = "https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js"  # Pinned Bootstrap bundle.
TWEETNACL_URL = "https://cdn.jsdelivr.net/npm/tweetnacl@1.0.3/nacl-fast.min.js"  # Browser-side Ed25519 implementation.
JS_SHA256_URL = "https://cdn.jsdelivr.net/npm/js-sha256@0.11.1/build/sha256.min.js"  # Incremental browser-side SHA-256 implementation.

# -----------------------------------------------------------------------------
# Embedded interface styles
# -----------------------------------------------------------------------------

THEME_CSS = r"""
:root{--page:#170900;--nav:#762100;--surface:#2a1100;--raised:#351700;--soft:#4b2000;--primary:#ff4d00;--accent:#ffad00;--text:#ffd900;--muted:#bd8100;--border:#783600;--success:#00a000;--danger:#d00000;--warning:#d89000;--black:#000000;--shadow:rgba(0,0,0,.28);--focus:rgba(255,77,0,.28);--bs-blue:#000000;--bs-indigo:#000000;--bs-purple:#000000;--bs-primary:#ff4d00;--bs-primary-rgb:255,77,0;--bs-info:#d89000;--bs-info-rgb:216,144,0;--bs-body-bg:var(--page);--bs-body-color:var(--text);--bs-border-color:var(--border);--bs-secondary-color:var(--muted);--bs-link-color:var(--accent);--bs-link-color-rgb:255,173,0;--bs-link-hover-color:var(--primary);--bs-link-hover-color-rgb:255,77,0;--bs-focus-ring-color:var(--focus)}
*{scrollbar-color:var(--primary) var(--raised)}::selection{background:var(--primary);color:var(--black)}html,body{min-height:100%;background:var(--page);color:var(--text)}body{font-size:.96rem}a,.btn-link{color:var(--accent)}a:hover,.btn-link:hover{color:var(--primary)}code{color:var(--accent)}
.navbar{min-height:42px;background:var(--nav);border-bottom:1px solid var(--primary);box-shadow:0 .2rem .55rem var(--shadow)}.navbar-brand{color:var(--text)!important;font-size:.94rem;font-weight:800}.navbar-brand small{display:block;color:var(--muted);font-size:.62rem;font-weight:500;line-height:1}.navbar .nav-link{color:var(--muted);font-size:.86rem;padding:.25rem .55rem}.navbar .nav-link.active,.navbar .nav-link:hover{color:var(--text)}.brand-mark{display:grid;place-items:center;width:1.75rem;height:1.75rem;border-radius:.35rem;background:var(--primary);color:var(--black);font-weight:900}.navbar-toggler{color:var(--accent);border-color:var(--primary)}
.card,.hero-panel{background:var(--surface);border:1px solid var(--border);border-radius:.85rem;box-shadow:0 .5rem 1.25rem var(--shadow);color:var(--text)}.card-header{background:var(--raised);border-bottom:1px solid var(--border);color:var(--text);font-weight:750}.section-note{background:var(--raised);border-left:.3rem solid var(--primary);border-radius:.45rem;color:var(--text)}.hash-entry{background:var(--raised);border:1px solid var(--border);border-radius:.7rem}.manifest-box{background:var(--raised);border:1px solid var(--border);border-radius:.7rem;white-space:pre-wrap}.monospace{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;word-break:break-all}.small-muted,.text-secondary{color:var(--muted)!important}.text-success{color:var(--success)!important}.text-danger{color:var(--danger)!important}.text-warning{color:var(--warning)!important}.status{min-height:1.35rem;white-space:pre-wrap}
.form-control,.form-select{background:var(--raised);border-color:var(--border);color:var(--text)}.form-control::placeholder{color:var(--muted)}.form-control:focus,.form-select:focus{background:var(--raised);border-color:var(--primary);box-shadow:0 0 0 .2rem var(--focus);color:var(--text)}.form-control[readonly]{background:var(--soft);color:var(--text)}.form-control::file-selector-button{background:var(--soft);border-color:var(--border);color:var(--text)}.form-control:hover:not(:disabled):not([readonly])::file-selector-button{background:var(--primary);color:var(--black)}.form-check-input{background-color:var(--raised);border-color:var(--border)}.form-check-input:checked{background-color:var(--primary);border-color:var(--primary)}
.btn{box-shadow:none!important}.btn-theme{--bs-btn-color:var(--black);--bs-btn-bg:var(--primary);--bs-btn-border-color:var(--primary);--bs-btn-hover-color:var(--black);--bs-btn-hover-bg:var(--accent);--bs-btn-hover-border-color:var(--accent);--bs-btn-focus-shadow-rgb:255,77,0;--bs-btn-active-color:var(--text);--bs-btn-active-bg:#a52f00;--bs-btn-active-border-color:#a52f00;--bs-btn-disabled-color:var(--black);--bs-btn-disabled-bg:var(--muted);--bs-btn-disabled-border-color:var(--muted)}.btn-outline-theme{--bs-btn-color:var(--accent);--bs-btn-border-color:var(--primary);--bs-btn-hover-color:var(--black);--bs-btn-hover-bg:var(--primary);--bs-btn-hover-border-color:var(--primary);--bs-btn-focus-shadow-rgb:255,77,0;--bs-btn-active-color:var(--black);--bs-btn-active-bg:var(--accent);--bs-btn-active-border-color:var(--accent)}
.progress{height:.7rem;background:var(--raised);border:1px solid var(--border)}.progress-bar{background:var(--primary)}.badge-valid{background:var(--success)!important;color:var(--black)!important}.badge-invalid{background:var(--danger)!important;color:var(--text)!important}.badge-neutral{background:var(--soft)!important;color:var(--text)!important}.badge-warning{background:var(--warning)!important;color:var(--black)!important}.alert{background:var(--raised);border-color:var(--border);color:var(--text)}.table{--bs-table-bg:transparent;--bs-table-color:var(--text);--bs-table-border-color:var(--border)}.dropdown-menu{--bs-dropdown-bg:var(--raised);--bs-dropdown-color:var(--text);--bs-dropdown-link-color:var(--text);--bs-dropdown-link-hover-bg:var(--primary);--bs-dropdown-link-hover-color:var(--black);--bs-dropdown-border-color:var(--border)}footer{color:var(--muted)}hr{border-color:var(--border);opacity:1}
@media(max-width:767.98px){.navbar-brand small{display:none}.navbar-collapse{padding-bottom:.35rem}}
"""

# -----------------------------------------------------------------------------
# Embedded shared browser cryptography and transport logic
# -----------------------------------------------------------------------------

COMMON_JAVASCRIPT = r"""
"use strict";
// -----------------------------------------------------------------------------
// Shared browser-side encoding, hashing, signing, verification, and AJAX helpers
// -----------------------------------------------------------------------------
const VideoPlatformClient={  // Deliberately exposes only deterministic protocol helpers.
    encoder:new TextEncoder(),
    hashPattern:/^[0-9a-f]{64}$/,
    publicKeyPattern:/^ed25519:[A-Za-z0-9_-]{43}$/,
    element(identifier){return document.getElementById(identifier);},
    setStatus(identifier,message,state="secondary"){
        const target=this.element(identifier);
        target.textContent=message;
        target.className=`status small mt-2 text-${state}`;
    },
    escapeHtml(value){return String(value).replace(/[&<>"']/g,character=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[character]));},
    bytesToBase64Url(bytes){
        let binary="";
        for(let offset=0;offset<bytes.length;offset+=8192)binary+=String.fromCharCode(...bytes.subarray(offset,offset+8192));
        return btoa(binary).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");
    },
    base64UrlToBytes(text){
        const normalized=String(text).replace(/-/g,"+").replace(/_/g,"/");
        const binary=atob(normalized+"=".repeat((4-normalized.length%4)%4));
        return Uint8Array.from(binary,character=>character.charCodeAt(0));
    },
    normalizePublicKey(value){
        let text=String(value||"").trim();
        if(!text.startsWith("ed25519:"))text=`ed25519:${text}`;
        if(!this.publicKeyPattern.test(text))throw new Error("Public key must contain a 32-byte Ed25519 key.");
        const bytes=this.base64UrlToBytes(text.slice("ed25519:".length));
        if(bytes.length!==32)throw new Error("Ed25519 public key must contain exactly 32 bytes.");
        return {text:`ed25519:${this.bytesToBase64Url(bytes)}`,bytes};
    },
    parsePrivateKey(value){
        let text=String(value||"").trim();
        if(!text)throw new Error("Enter or import an Ed25519 private key.");
        let declaredPublicKey="";
        if(text.startsWith("{")){
            const record=JSON.parse(text);
            text=String(record.private_key||"").trim();
            declaredPublicKey=String(record.public_key||"").trim();
        }
        if(text.startsWith("ed25519-private:"))text=text.slice("ed25519-private:".length);
        let seed;
        if(/^[0-9a-fA-F]{64}$/.test(text))seed=Uint8Array.from(text.match(/../g),pair=>parseInt(pair,16));
        else seed=this.base64UrlToBytes(text);
        if(seed.length!==32)throw new Error("Private key must be a 32-byte Ed25519 seed.");
        const keyPair=nacl.sign.keyPair.fromSeed(seed);
        const privateKey=`ed25519-private:${this.bytesToBase64Url(seed)}`;
        const publicKey=`ed25519:${this.bytesToBase64Url(keyPair.publicKey)}`;
        if(declaredPublicKey&&this.normalizePublicKey(declaredPublicKey).text!==publicKey)throw new Error("The imported public key does not match the private key.");
        return {seed,privateKey,publicKey,publicKeyBytes:keyPair.publicKey};
    },
    canonicalHashes(hashes){
        const normalized=[...new Set(hashes.map(value=>String(value).trim().toLowerCase()))].sort();
        if(!normalized.length)throw new Error("At least one video hash is required.");
        if(normalized.length>10000)throw new Error("The manifest contains too many hashes.");
        if(normalized.some(value=>!this.hashPattern.test(value)))throw new Error("The manifest contains an invalid SHA-256 value.");
        return normalized;
    },
    normalizeRevision(value){
        const revision=Number(value);
        if(!Number.isSafeInteger(revision)||revision<1)throw new Error("Manifest revision must be a positive integer.");
        return revision;
    },
    normalizePreviousSignatureHash(value,revision){
        if(revision===1){
            if(value!==null&&value!==undefined&&value!=="")throw new Error("Revision 1 cannot reference a previous signature.");
            return null;
        }
        const normalized=String(value||"").trim().toLowerCase();
        if(!this.hashPattern.test(normalized))throw new Error("A later revision must reference the previous signature SHA-256.");
        return normalized;
    },
    normalizeTimestamp(value,label){
        const text=String(value||"").trim();
        if(!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})$/.test(text))throw new Error(`${label} must be an ISO 8601 timestamp with a timezone offset.`);
        const moment=new Date(text);
        if(Number.isNaN(moment.getTime()))throw new Error(`${label} is invalid.`);
        return text;
    },
    buildPublicationNote(signedAt,expiresAt){return `Signed at ${signedAt}; expires at ${expiresAt}.`;},
    normalizeNote(value,signedAt,expiresAt){
        const note=String(value||"").trim();
        const expected=this.buildPublicationNote(signedAt,expiresAt);
        if(note!==expected)throw new Error("Manifest note must exactly describe its signed and expiration times.");
        return note;
    },
    isoWithTimezone(date){
        if(!(date instanceof Date)||Number.isNaN(date.getTime()))throw new Error("Timestamp is invalid.");
        const pad=value=>String(value).padStart(2,"0");
        const offsetMinutes=-date.getTimezoneOffset();
        const sign=offsetMinutes>=0?"+":"-";
        const absolute=Math.abs(offsetMinutes);
        return `${date.getFullYear()}-${pad(date.getMonth()+1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}${sign}${pad(Math.floor(absolute/60))}:${pad(absolute%60)}`;
    },
    dateTimeLocalValue(date){
        const pad=value=>String(value).padStart(2,"0");
        return `${date.getFullYear()}-${pad(date.getMonth()+1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
    },
    canonicalManifest(publicKey,hashes,revision,previousSignatureSha256,signedAt=null,expiresAt=null,note=null){
        const normalizedRevision=this.normalizeRevision(revision);
        const base={public_key:this.normalizePublicKey(publicKey).text,revision:normalizedRevision,previous_signature_sha256:this.normalizePreviousSignatureHash(previousSignatureSha256,normalizedRevision)};
        const hasTemporalFields=[signedAt,expiresAt,note].some(value=>value!==null&&value!==undefined&&value!=="");
        if(!hasTemporalFields)return {...base,hashes:this.canonicalHashes(hashes)};
        const normalizedSignedAt=this.normalizeTimestamp(signedAt,"Signed time");
        const normalizedExpiresAt=this.normalizeTimestamp(expiresAt,"Expiration time");
        if(new Date(normalizedExpiresAt).getTime()<=new Date(normalizedSignedAt).getTime())throw new Error("Expiration time must be later than signed time.");
        return {...base,signed_at:normalizedSignedAt,expires_at:normalizedExpiresAt,note:this.normalizeNote(note,normalizedSignedAt,normalizedExpiresAt),hashes:this.canonicalHashes(hashes)};
    },
    buildManifestMessage(publicKey,hashes,revision,previousSignatureSha256,signedAt=null,expiresAt=null,note=null){
        return JSON.stringify(this.canonicalManifest(publicKey,hashes,revision,previousSignatureSha256,signedAt,expiresAt,note));
    },
    signManifest(identity,hashes,revision,previousSignatureSha256,signedAt,expiresAt,note){
        const message=this.encoder.encode(this.buildManifestMessage(identity.publicKey,hashes,revision,previousSignatureSha256,signedAt,expiresAt,note));
        const secretKey=nacl.sign.keyPair.fromSeed(identity.seed).secretKey;
        return this.bytesToBase64Url(nacl.sign.detached(message,secretKey));
    },
    verifyManifest(manifest){
        try{
            const canonical=this.canonicalManifest(manifest.public_key,manifest.hashes,manifest.revision,manifest.previous_signature_sha256,manifest.signed_at,manifest.expires_at,manifest.note);
            const signature=this.base64UrlToBytes(manifest.signature);
            const publicKey=this.normalizePublicKey(canonical.public_key);
            const message=this.encoder.encode(JSON.stringify(canonical));
            return signature.length===64&&nacl.sign.detached.verify(message,signature,publicKey.bytes);
        }catch{return false;}
    },
    manifestTimeStatus(manifest){
        if(!manifest.signed_at||!manifest.expires_at)return {legacy:true,expired:false,future:false,label:"legacy manifest without signed expiration"};
        const now=Date.now();
        const signedAt=new Date(manifest.signed_at).getTime();
        const expiresAt=new Date(manifest.expires_at).getTime();
        return {legacy:false,expired:expiresAt<=now,future:signedAt>now+15*60*1000,label:expiresAt<=now?"expired":signedAt>now+15*60*1000?"signed time is in the future":"currently valid"};
    },
    signatureSha256(signature){
        const calculator=sha256.create();
        calculator.update(this.base64UrlToBytes(signature));
        return calculator.hex();
    },
    revisionStorageKey(publicKey){return `dshvp-highest-revision:${this.normalizePublicKey(publicKey).text}`;},
    enforceAndRememberRevision(manifest){
        const key=this.revisionStorageKey(manifest.public_key);
        const known=Number(localStorage.getItem(key)||"0");
        const revision=this.normalizeRevision(manifest.revision);
        if(known>revision)throw new Error(`Possible server rollback detected. This browser previously verified revision ${known}, but the server returned revision ${revision}.`);
        if(revision>known)localStorage.setItem(key,String(revision));
    },
    async hashFileSequentially(file,progressCallback){
        const calculator=sha256.create();
        const chunkSize=4*1024*1024;
        const totalSize=Math.max(file.size,1);
        for(let offset=0;offset<file.size;offset+=chunkSize){
            const bytes=new Uint8Array(await file.slice(offset,offset+chunkSize).arrayBuffer());
            calculator.update(bytes);
            if(progressCallback)progressCallback(Math.min(1,(offset+bytes.length)/totalSize));
            await new Promise(resolve=>setTimeout(resolve,0));
        }
        if(file.size===0&&progressCallback)progressCallback(1);
        return calculator.hex();
    },
    async requestJson(url,options={}){
        options.headers=options.headers||{};
        if(options.body&&!(options.body instanceof FormData))options.headers["Content-Type"]="application/json";
        const response=await fetch(url,options);
        const payload=await response.json().catch(()=>({error:"The server returned an invalid response."}));
        if(!response.ok){
            const error=new Error(payload.error||`HTTP ${response.status}`);
            error.payload=payload;
            throw error;
        }
        return payload;
    },
    downloadText(fileName,text,type="text/plain"){
        const link=document.createElement("a");
        link.href=URL.createObjectURL(new Blob([text],{type}));
        link.download=fileName;
        link.click();
        URL.revokeObjectURL(link.href);
    },
    async verifiedDownload(objectHash,statusIdentifier){
        this.setStatus(statusIdentifier,`Downloading ${objectHash}…`,"secondary");
        const response=await fetch(`/object/${objectHash}`);
        if(!response.ok){
            const payload=await response.json().catch(()=>({error:"Download failed."}));
            throw new Error(payload.error||"Download failed.");
        }
        const reader=response.body.getReader();
        const calculator=sha256.create();
        const chunks=[];
        let received=0;
        while(true){
            const result=await reader.read();
            if(result.done)break;
            calculator.update(result.value);
            chunks.push(result.value);
            received+=result.value.length;
            this.setStatus(statusIdentifier,`Downloaded ${received.toLocaleString()} bytes; verifying SHA-256…`,"secondary");
        }
        const actualHash=calculator.hex();
        if(actualHash!==objectHash)throw new Error(`Downloaded content failed SHA-256 verification. Actual hash: ${actualHash}`);
        const contentType=response.headers.get("Content-Type")||"application/octet-stream";
        const downloadName=response.headers.get("X-Download-Filename")||objectHash;
        const link=document.createElement("a");
        link.href=URL.createObjectURL(new Blob(chunks,{type:contentType}));
        link.download=downloadName;
        link.click();
        URL.revokeObjectURL(link.href);
        this.setStatus(statusIdentifier,"Download complete. Browser-side SHA-256 verification passed.","success");
    }
};
window.VideoPlatformClient=VideoPlatformClient;  // Publish one auditable namespace for page-specific scripts.
window.addEventListener("DOMContentLoaded",()=>{
    if(typeof nacl==="undefined"||typeof sha256==="undefined")document.body.innerHTML='<main class="container py-5"><div class="alert">Cryptography libraries could not be loaded from the configured CDN URLs.</div></main>';
});
"""

# -----------------------------------------------------------------------------
# Embedded identity-page logic
# -----------------------------------------------------------------------------

IDENTITY_JAVASCRIPT = r"""
"use strict";
// -----------------------------------------------------------------------------
// Local Ed25519 identity generation
// -----------------------------------------------------------------------------
let currentIdentity=null;  // Keeps the generated key pair in browser memory only.
function renderIdentity(identity){
    currentIdentity=identity;
    VideoPlatformClient.element("privateKeyOutput").value=identity.privateKey;
    VideoPlatformClient.element("publicKeyOutput").value=identity.publicKey;
    VideoPlatformClient.element("downloadIdentityButton").disabled=false;
    VideoPlatformClient.setStatus("identityStatus","A new Ed25519 key pair was generated locally. The private key was not sent to the server.","success");
}
window.addEventListener("DOMContentLoaded",()=>{
    VideoPlatformClient.element("generateIdentityButton").addEventListener("click",()=>{
        const keyPair=nacl.sign.keyPair();
        const seed=keyPair.secretKey.slice(0,32);
        renderIdentity({privateKey:`ed25519-private:${VideoPlatformClient.bytesToBase64Url(seed)}`,publicKey:`ed25519:${VideoPlatformClient.bytesToBase64Url(keyPair.publicKey)}`});
    });
    VideoPlatformClient.element("copyPrivateKeyButton").addEventListener("click",async()=>{
        await navigator.clipboard.writeText(VideoPlatformClient.element("privateKeyOutput").value);
        VideoPlatformClient.setStatus("identityStatus","Private key copied.","success");
    });
    VideoPlatformClient.element("copyPublicKeyButton").addEventListener("click",async()=>{
        await navigator.clipboard.writeText(VideoPlatformClient.element("publicKeyOutput").value);
        VideoPlatformClient.setStatus("identityStatus","Public key copied.","success");
    });
    VideoPlatformClient.element("downloadIdentityButton").addEventListener("click",()=>{
        if(!currentIdentity)return;
        VideoPlatformClient.downloadText("ed25519-key-pair.json",JSON.stringify({private_key:currentIdentity.privateKey,public_key:currentIdentity.publicKey},null,2),"application/json");
    });
});
"""

# -----------------------------------------------------------------------------
# Embedded two-phase publication logic
# -----------------------------------------------------------------------------

PUBLISH_JAVASCRIPT = r"""
"use strict";
// -----------------------------------------------------------------------------
// Sequential hashing and two-phase signed publication
// -----------------------------------------------------------------------------
let currentIdentity=null;  // Parsed private seed and locally derived public key.
let selectedFilesByHash=new Map();  // Deduplicates selected files by their SHA-256 address.
let signedManifestDraft=null;  // Canonical manifest submitted before any missing video bytes.

function loadIdentityFromInput(){
    currentIdentity=VideoPlatformClient.parsePrivateKey(VideoPlatformClient.element("privateKeyInput").value);
    VideoPlatformClient.element("derivedPublicKey").value=currentIdentity.publicKey;
    return currentIdentity;
}

async function hashSelectedFiles(files){
    selectedFilesByHash=new Map();
    const resultContainer=VideoPlatformClient.element("hashResults");
    resultContainer.innerHTML="";
    for(let index=0;index<files.length;index++){
        const file=files[index];
        const hashResultElement=document.createElement("div");
        hashResultElement.className="hash-entry p-3 mb-2";
        hashResultElement.innerHTML=`<div class="d-flex justify-content-between gap-3"><strong>${VideoPlatformClient.escapeHtml(file.name)}</strong><span>${index+1}/${files.length}</span></div><div class="small-muted mt-1">Calculating SHA-256 sequentially…</div><div class="progress mt-2"><div class="progress-bar" style="width:0%"></div></div><div class="monospace small mt-2"></div>`;
        resultContainer.appendChild(hashResultElement);
        const progressBar=hashResultElement.querySelector(".progress-bar");
        const hashOutput=hashResultElement.querySelector(".monospace");
        const fileHash=await VideoPlatformClient.hashFileSequentially(file,ratio=>{progressBar.style.width=`${Math.round(ratio*100)}%`;});
        hashOutput.textContent=fileHash;
        if(!selectedFilesByHash.has(fileHash))selectedFilesByHash.set(fileHash,file);
        VideoPlatformClient.element("overallProgress").style.width=`${Math.round((index+1)/files.length*45)}%`;
    }
    return [...selectedFilesByHash.keys()].sort();
}

async function uploadMissingObject(token,objectHash,file,completed,total){
    const formData=new FormData();
    formData.append("video",file,file.name||objectHash);
    const response=await fetch(`/api/publish/upload/${encodeURIComponent(token)}/${objectHash}`,{method:"POST",body:formData});
    const payload=await response.json().catch(()=>({error:"The server returned an invalid upload response."}));
    if(!response.ok)throw new Error(payload.error||"Object upload failed.");
    VideoPlatformClient.element("overallProgress").style.width=`${45+Math.round((completed+1)/Math.max(total,1)*45)}%`;
}

function renderReceipt(manifest,reusedCount,uploadedCount){
    VideoPlatformClient.element("receiptPanel").classList.remove("d-none");
    VideoPlatformClient.element("receiptContent").textContent=JSON.stringify(manifest,null,2);
    VideoPlatformClient.element("receiptSummary").textContent=`Revision ${manifest.revision} · signed ${manifest.signed_at} · expires ${manifest.expires_at} · ${manifest.hashes.length} signed hashes · ${reusedCount} existing objects reused · ${uploadedCount} objects uploaded`;
}

window.addEventListener("DOMContentLoaded",()=>{
    const defaultExpiration=new Date();
    defaultExpiration.setFullYear(defaultExpiration.getFullYear()+1);
    VideoPlatformClient.element("manifestExpiresAt").value=VideoPlatformClient.dateTimeLocalValue(defaultExpiration);
    const refreshNote=()=>{
        const expirationValue=VideoPlatformClient.element("manifestExpiresAt").value;
        if(!expirationValue){VideoPlatformClient.element("manifestNote").value="";return;}
        const signedAt=VideoPlatformClient.isoWithTimezone(new Date());
        const expiresAt=VideoPlatformClient.isoWithTimezone(new Date(expirationValue));
        VideoPlatformClient.element("manifestNote").value=VideoPlatformClient.buildPublicationNote(signedAt,expiresAt);
    };
    refreshNote();
    VideoPlatformClient.element("manifestExpiresAt").addEventListener("input",refreshNote);
    VideoPlatformClient.element("privateKeyFile").addEventListener("change",async event=>{
        const file=event.target.files[0];
        if(!file)return;
        VideoPlatformClient.element("privateKeyInput").value=await file.text();
        try{loadIdentityFromInput();VideoPlatformClient.setStatus("publishStatus","Private key imported and public key derived.","success");}
        catch(error){VideoPlatformClient.setStatus("publishStatus",error.message,"danger");}
    });
    VideoPlatformClient.element("privateKeyInput").addEventListener("input",()=>{
        try{loadIdentityFromInput();VideoPlatformClient.setStatus("publishStatus","Private key accepted. Public key derived locally.","success");}
        catch{VideoPlatformClient.element("derivedPublicKey").value="";}
    });
    VideoPlatformClient.element("downloadReceiptButton").addEventListener("click",()=>VideoPlatformClient.downloadText("signed-manifest.json",VideoPlatformClient.element("receiptContent").textContent,"application/json"));
    VideoPlatformClient.element("publishButton").addEventListener("click",async()=>{
        try{
            VideoPlatformClient.element("publishButton").disabled=true;
            VideoPlatformClient.element("overallProgress").style.width="0%";
            VideoPlatformClient.element("receiptPanel").classList.add("d-none");
            const identity=loadIdentityFromInput();
            const files=[...VideoPlatformClient.element("videoFilesInput").files];
            if(!files.length)throw new Error("Select every video that should appear in the current manifest.");
            VideoPlatformClient.setStatus("publishStatus","Calculating every video SHA-256 sequentially…","secondary");
            const hashes=await hashSelectedFiles(files);
            const manifestState=await VideoPlatformClient.requestJson(`/api/manifest-state?public_key=${encodeURIComponent(identity.publicKey)}`);
            const revision=manifestState.current_revision+1;
            const previousSignatureSha256=manifestState.current_signature_sha256;
            const signedAt=VideoPlatformClient.isoWithTimezone(new Date());
            const expirationInput=VideoPlatformClient.element("manifestExpiresAt").value;
            if(!expirationInput)throw new Error("Choose a manifest expiration time.");
            const expiresAt=VideoPlatformClient.isoWithTimezone(new Date(expirationInput));
            const note=VideoPlatformClient.buildPublicationNote(signedAt,expiresAt);
            VideoPlatformClient.element("manifestNote").value=note;
            const signature=VideoPlatformClient.signManifest(identity,hashes,revision,previousSignatureSha256,signedAt,expiresAt,note);
            signedManifestDraft={public_key:identity.publicKey,revision,previous_signature_sha256:previousSignatureSha256,signed_at:signedAt,expires_at:expiresAt,note,hashes,signature};
            VideoPlatformClient.setStatus("publishStatus",`Submitting signed revision ${revision} for server-side Ed25519 verification…`,"secondary");
            const preparation=await VideoPlatformClient.requestJson("/api/publish/prepare",{method:"POST",body:JSON.stringify(signedManifestDraft)});
            if(!preparation.signature_valid)throw new Error("The server did not accept the manifest signature.");
            for(let index=0;index<preparation.missing_hashes.length;index++){
                const objectHash=preparation.missing_hashes[index];
                const file=selectedFilesByHash.get(objectHash);
                if(!file)throw new Error(`The selected file for ${objectHash} is unavailable.`);
                VideoPlatformClient.setStatus("publishStatus",`Uploading missing object ${index+1}/${preparation.missing_hashes.length}: ${objectHash}`,"secondary");
                await uploadMissingObject(preparation.token,objectHash,file,index,preparation.missing_hashes.length);
            }
            VideoPlatformClient.setStatus("publishStatus","Finalizing the atomic replacement of the current signed manifest…","secondary");
            const finalizationResponse=await VideoPlatformClient.requestJson("/api/publish/finalize",{method:"POST",body:JSON.stringify({token:preparation.token})});
            if(!VideoPlatformClient.verifyManifest(finalizationResponse.manifest))throw new Error("The finalized manifest failed browser-side Ed25519 verification.");
            VideoPlatformClient.enforceAndRememberRevision(finalizationResponse.manifest);
            VideoPlatformClient.element("overallProgress").style.width="100%";
            renderReceipt(finalizationResponse.manifest,preparation.reused_hashes.length,preparation.missing_hashes.length);
            VideoPlatformClient.setStatus("publishStatus",`Revision ${finalizationResponse.manifest.revision} is now the only current manifest for this public key.`,"success");
        }catch(error){VideoPlatformClient.setStatus("publishStatus",error.message,"danger");}
        finally{VideoPlatformClient.element("publishButton").disabled=false;}
    });
});
"""

# -----------------------------------------------------------------------------
# Embedded search, signature verification, and download logic
# -----------------------------------------------------------------------------

SEARCH_JAVASCRIPT = r"""
"use strict";
// -----------------------------------------------------------------------------
// Browser-side verification of search results and downloaded objects
// -----------------------------------------------------------------------------
function objectStatusMap(manifest){return new Map((manifest.objects||[]).map(item=>[item.hash,item]));}
function verifyReturnedManifest(manifest,query){
    if(!VideoPlatformClient.verifyManifest(manifest))throw new Error(`Invalid Ed25519 signature returned for public key ${manifest.public_key}.`);
    const canonicalHashes=VideoPlatformClient.canonicalHashes(manifest.hashes);
    if(JSON.stringify(canonicalHashes)!==JSON.stringify(manifest.hashes))throw new Error("The server returned a non-canonical or duplicated hash list.");
    if(VideoPlatformClient.hashPattern.test(query)&&!canonicalHashes.includes(query))throw new Error("The returned signed manifest does not contain the searched video hash.");
    if(VideoPlatformClient.publicKeyPattern.test(query)&&manifest.public_key!==query)throw new Error("The returned manifest public key does not match the searched public key.");
    const timeStatus=VideoPlatformClient.manifestTimeStatus(manifest);
    if(timeStatus.future)throw new Error("The returned manifest has a signed time too far in the future.");
    manifest.browser_time_status=timeStatus;
    VideoPlatformClient.enforceAndRememberRevision(manifest);
}
function renderSearchResults(manifests){
    if(!manifests.length){VideoPlatformClient.element("searchResults").innerHTML='<div class="alert mt-3">No current signed manifest matched the query.</div>';return;}
    VideoPlatformClient.element("searchResults").innerHTML=manifests.map((manifest,manifestIndex)=>{
        const statuses=objectStatusMap(manifest);
        const hashes=manifest.hashes.map((hash,index)=>{
            const status=statuses.get(hash)||{exists:false,valid:false};
            const manifestExpired=manifest.browser_time_status&&manifest.browser_time_status.expired;
            const valid=status.exists&&status.valid&&!manifestExpired;
            const badge=manifestExpired?'<span class="badge badge-warning">signed manifest expired</span>':status.exists&&status.valid?'<span class="badge badge-valid">available and valid</span>':status.exists?'<span class="badge badge-invalid">hash mismatch</span>':'<span class="badge badge-invalid">missing</span>';
            const action=valid?`<button class="btn btn-sm btn-outline-theme download-object" data-hash="${hash}" data-status="downloadStatus${manifestIndex}">Verify & download ${VideoPlatformClient.escapeHtml(status.extension||"")}</button>`:"";
            return `<div class="hash-entry p-3 mb-2"><div class="d-flex flex-wrap justify-content-between gap-2"><span class="monospace">${index+1}. ${hash}</span><span>${badge} ${action}</span></div></div>`;
        }).join("");
        const signedContent={public_key:manifest.public_key,revision:manifest.revision,previous_signature_sha256:manifest.previous_signature_sha256};
        if(manifest.signed_at){signedContent.signed_at=manifest.signed_at;signedContent.expires_at=manifest.expires_at;signedContent.note=manifest.note;}
        signedContent.hashes=manifest.hashes;
        const timeStatus=manifest.browser_time_status||VideoPlatformClient.manifestTimeStatus(manifest);
        const timeBadge=timeStatus.legacy?'<span class="badge badge-warning">legacy: no signed expiration</span>':timeStatus.expired?'<span class="badge badge-warning">expired</span>':'<span class="badge badge-valid">time-valid</span>';
        return `<section class="card mt-4"><div class="card-header">Browser-verified current manifest · revision ${manifest.revision} · ${timeBadge}</div><div class="card-body"><div class="small-muted mb-1">Public key</div><div class="monospace mb-3">${VideoPlatformClient.escapeHtml(manifest.public_key)}</div><div class="small-muted mb-1">Detached Ed25519 signature</div><div class="monospace mb-3">${VideoPlatformClient.escapeHtml(manifest.signature)}</div><div class="small-muted mb-1">Signed content</div><pre class="manifest-box p-3 monospace small">${VideoPlatformClient.escapeHtml(JSON.stringify(signedContent,null,2))}</pre><hr><div>${hashes}</div><div id="downloadStatus${manifestIndex}" class="status small mt-2"></div></div></section>`;
    }).join("");
    document.querySelectorAll(".download-object").forEach(button=>button.addEventListener("click",async()=>{
        try{await VideoPlatformClient.verifiedDownload(button.dataset.hash,button.dataset.status);}
        catch(error){VideoPlatformClient.setStatus(button.dataset.status,error.message,"danger");}
    }));
}
window.addEventListener("DOMContentLoaded",()=>{
    VideoPlatformClient.element("searchButton").addEventListener("click",async()=>{
        try{
            const query=VideoPlatformClient.element("searchInput").value.trim();
            if(!query)throw new Error("Enter an Ed25519 public key or a SHA-256 video hash.");
            const normalizedQuery=VideoPlatformClient.hashPattern.test(query.toLowerCase())?query.toLowerCase():VideoPlatformClient.normalizePublicKey(query).text;
            VideoPlatformClient.setStatus("searchStatus","Requesting results and independently verifying every returned Ed25519 signature…","secondary");
            const response=await VideoPlatformClient.requestJson(`/api/search?q=${encodeURIComponent(normalizedQuery)}`);
            for(const manifest of response.manifests)verifyReturnedManifest(manifest,normalizedQuery);
            renderSearchResults(response.manifests);
            VideoPlatformClient.setStatus("searchStatus",`${response.manifests.length} current manifest(s) returned. Every displayed signature passed browser-side verification.`,"success");
        }catch(error){VideoPlatformClient.element("searchResults").innerHTML="";VideoPlatformClient.setStatus("searchStatus",error.message,"danger");}
    });
});
"""

# -----------------------------------------------------------------------------
# Embedded HTML templates
# -----------------------------------------------------------------------------

BASE_TEMPLATE = r"""
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{ title }} · Digital Signature Hash Video Platform</title><link href="{{ bootstrap_css_url }}" rel="stylesheet"><style>{{ theme_css|safe }}</style></head><body>
<nav class="navbar navbar-expand-md"><div class="container"><a class="navbar-brand d-flex align-items-center gap-2" href="/"><span class="brand-mark">H</span><span>Digital Signature Hash Video Platform<small>Ed25519 + SHA-256</small></span></a><button class="navbar-toggler btn btn-outline-theme" type="button" data-bs-toggle="collapse" data-bs-target="#navigation">Menu</button><div id="navigation" class="collapse navbar-collapse"><div class="navbar-nav ms-auto"><a class="nav-link {{ 'active' if active_page == 'home' else '' }}" href="/">Home</a><a class="nav-link {{ 'active' if active_page == 'identity' else '' }}" href="/identity">Identity</a><a class="nav-link {{ 'active' if active_page == 'publish' else '' }}" href="/publish">Publish</a><a class="nav-link {{ 'active' if active_page == 'search' else '' }}" href="/search">Search</a></div></div></div></nav>
<main class="container py-4">{{ content|safe }}</main><footer class="container pb-4 small"><hr><span>AGPL-3.0-or-later · <a href="{{ source_code_url }}">Source code</a></span></footer>
<script src="{{ bootstrap_js_url }}"></script><script src="{{ tweetnacl_url }}"></script><script src="{{ js_sha256_url }}"></script><script>{{ common_javascript|safe }}</script>{% if page_javascript %}<script>{{ page_javascript|safe }}</script>{% endif %}</body></html>
"""

HOME_CONTENT = r"""
<section class="hero-panel p-4 p-lg-5"><div class="row align-items-center g-4"><div class="col-lg-8"><h1 class="display-6 fw-bold">Signed video hash lists and content-addressed storage.</h1><p class="lead mb-3">Every selected video receives its own SHA-256 hash. One Ed25519 signature covers the complete canonical list of those hashes. Search by public key or video hash, verify the returned signature in the browser, and download by hash.</p><div class="d-flex flex-wrap gap-2"><a class="btn btn-theme" href="/identity">Generate identity</a><a class="btn btn-outline-theme" href="/publish">Publish videos</a><a class="btn btn-outline-theme" href="/search">Search and verify</a></div></div><div class="col-lg-4"><div class="section-note p-3"><strong>One current manifest</strong><p class="small mb-0 mt-2">Submitting another correctly signed list with the same public key replaces the previous list. Existing video objects are reused by SHA-256 and are not stored twice.</p></div></div></div></section>
<section class="row g-3 mt-2"><div class="col-md-4"><div class="card h-100"><div class="card-body"><h2 class="h5">Ed25519 identity</h2><p class="mb-0 small-muted">The public key is the identity. The private seed signs locally and is never included in publication requests.</p></div></div></div><div class="col-md-4"><div class="card h-100"><div class="card-body"><h2 class="h5">SHA-256 objects</h2><p class="mb-0 small-muted">Identical files have the same hash and share one stored object. Modified files produce a different hash.</p></div></div></div><div class="col-md-4"><div class="card h-100"><div class="card-body"><h2 class="h5">Two-phase AJAX</h2><p class="mb-0 small-muted">The signature is verified first. Only missing objects are uploaded, then the current manifest is atomically replaced.</p></div></div></div></section>
<section class="alert mt-4"><strong>Security boundary:</strong> signatures and hashes expose forged identities, altered hash lists, and modified files. They cannot force a hostile server to keep data, return every result, or avoid denial of service.</section>
"""

IDENTITY_CONTENT = r"""
<div class="row justify-content-center"><div class="col-xl-9"><div class="card"><div class="card-header">Generate an Ed25519 identity</div><div class="card-body"><p class="small-muted">The generated key file contains only <code>private_key</code> and <code>public_key</code>. Keep the private key offline and protected.</p><button id="generateIdentityButton" class="btn btn-theme">Generate new key pair</button><label class="form-label mt-3">Private key</label><textarea id="privateKeyOutput" class="form-control monospace" rows="4" readonly></textarea><button id="copyPrivateKeyButton" class="btn btn-outline-theme mt-2">Copy private key</button><label class="form-label mt-3">Public key</label><textarea id="publicKeyOutput" class="form-control monospace" rows="3" readonly></textarea><button id="copyPublicKeyButton" class="btn btn-outline-theme mt-2">Copy public key</button><button id="downloadIdentityButton" class="btn btn-outline-theme mt-2" disabled>Download key file</button><div id="identityStatus" class="status small mt-2"></div></div></div></div></div>
"""

PUBLISH_CONTENT = r"""
<div class="row g-4"><div class="col-lg-5"><div class="card"><div class="card-header">1. Private key</div><div class="card-body"><p class="small-muted">Paste a 32-byte Ed25519 private seed or import a key file. The browser derives the public key automatically.</p><label class="form-label">Import private-key file</label><input id="privateKeyFile" class="form-control" type="file" accept=".json,.txt,application/json,text/plain"><label class="form-label mt-3">Private key text</label><textarea id="privateKeyInput" class="form-control monospace" rows="5" placeholder="ed25519-private:..."></textarea><label class="form-label mt-3">Derived public key</label><textarea id="derivedPublicKey" class="form-control monospace" rows="3" readonly></textarea></div></div></div><div class="col-lg-7"><div class="card"><div class="card-header">2. Complete current hash list</div><div class="card-body"><p class="small-muted">Select every video that should remain in this public key's current manifest. The browser hashes files one by one, signs the complete hash list and timestamp metadata, submits the signature first, uploads only missing objects, and replaces the previous list.</p><input id="videoFilesInput" class="form-control" type="file" accept="video/*" multiple><label class="form-label mt-3">Manifest expiration time</label><input id="manifestExpiresAt" class="form-control" type="datetime-local"><div class="small-muted mt-1">The browser signs the local timezone offset. Expired manifests remain auditable but are not offered as valid downloads.</div><label class="form-label mt-3">Automatic signed note</label><textarea id="manifestNote" class="form-control monospace" rows="3" readonly></textarea><button id="publishButton" class="btn btn-theme mt-3">Hash, sign, verify, upload, and replace</button><div class="progress mt-3"><div id="overallProgress" class="progress-bar" style="width:0%"></div></div><div id="publishStatus" class="status small mt-2"></div></div></div><div id="hashResults" class="mt-3"></div><div id="receiptPanel" class="card mt-3 d-none"><div class="card-header">Verified publication receipt</div><div class="card-body"><div id="receiptSummary" class="small-muted mb-2"></div><pre id="receiptContent" class="manifest-box p-3 monospace small"></pre><button id="downloadReceiptButton" class="btn btn-outline-theme">Download receipt</button></div></div></div></div>
"""

SEARCH_CONTENT = r"""
<div class="row justify-content-center"><div class="col-xl-10"><div class="card"><div class="card-header">Search signed manifests</div><div class="card-body"><p class="small-muted">Enter an Ed25519 public key to list its complete current signed hash list, or enter a SHA-256 video hash to find current manifests that contain it. The browser independently verifies every returned signature.</p><div class="input-group"><input id="searchInput" class="form-control monospace" placeholder="ed25519:... or 64-character SHA-256"><button id="searchButton" class="btn btn-theme">Search and verify</button></div><div id="searchStatus" class="status small mt-2"></div></div></div><div id="searchResults"></div></div></div>
"""


# -----------------------------------------------------------------------------
# Time and database helpers
# -----------------------------------------------------------------------------

def format_utc_timestamp(value: datetime | None = None) -> str:
    """Return a timezone-aware UTC timestamp in stable ISO 8601 form."""
    moment = value or datetime.now(timezone.utc)  # Use the supplied moment or the current UTC time.
    return moment.isoformat(timespec="seconds")


def get_database() -> sqlite3.Connection:
    """Open one request-scoped SQLite connection with integrity-safe pragmas."""
    if "database" not in g:
        connection = sqlite3.connect(DATABASE_PATH, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=30000")
        g.database = connection
    return g.database


@application.teardown_appcontext
def close_database(_: BaseException | None = None) -> None:
    """Close the request-scoped SQLite connection after Flask finishes a request."""
    connection = g.pop("database", None)  # Remove the connection from Flask request storage.
    if connection is not None:
        connection.close()


def initialize_database() -> None:
    """Create or migrate the object, manifest, index, and pending-publication tables."""
    connection = sqlite3.connect(DATABASE_PATH)  # Use a standalone connection during process startup.
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA foreign_keys=OFF")
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS objects(
            hash TEXT PRIMARY KEY,
            size INTEGER NOT NULL,
            path TEXT NOT NULL,
            created_at TEXT NOT NULL,
            mime_type TEXT,
            extension TEXT
        );
        CREATE TABLE IF NOT EXISTS manifests(
            public_key TEXT PRIMARY KEY,
            revision INTEGER NOT NULL,
            previous_signature_sha256 TEXT,
            signed_at TEXT,
            expires_at TEXT,
            note TEXT,
            hashes_json TEXT NOT NULL,
            signature TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS manifest_objects(
            public_key TEXT NOT NULL,
            object_hash TEXT NOT NULL,
            PRIMARY KEY(public_key, object_hash),
            FOREIGN KEY(public_key) REFERENCES manifests(public_key) ON DELETE CASCADE,
            FOREIGN KEY(object_hash) REFERENCES objects(hash) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS manifest_objects_hash_index ON manifest_objects(object_hash);
        """
    )
    object_columns = {row[1] for row in connection.execute("PRAGMA table_info(objects)").fetchall()}
    if "mime_type" not in object_columns:
        connection.execute("ALTER TABLE objects ADD COLUMN mime_type TEXT")
    if "extension" not in object_columns:
        connection.execute("ALTER TABLE objects ADD COLUMN extension TEXT")
    manifest_columns = {row[1] for row in connection.execute("PRAGMA table_info(manifests)").fetchall()}
    if "signed_at" not in manifest_columns:
        connection.execute("ALTER TABLE manifests ADD COLUMN signed_at TEXT")
    if "expires_at" not in manifest_columns:
        connection.execute("ALTER TABLE manifests ADD COLUMN expires_at TEXT")
    if "note" not in manifest_columns:
        connection.execute("ALTER TABLE manifests ADD COLUMN note TEXT")
    expected_pending_columns = {
        "token", "public_key", "revision", "previous_signature_sha256", "signed_at", "manifest_expires_at", "note",
        "hashes_json", "signature", "base_signature_sha256", "created_at", "expires_at"
    }
    pending_columns = {row[1] for row in connection.execute("PRAGMA table_info(pending_publications)").fetchall()}
    if pending_columns and pending_columns != expected_pending_columns:
        connection.execute("DROP TABLE pending_publications")
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS pending_publications(
            token TEXT PRIMARY KEY,
            public_key TEXT NOT NULL,
            revision INTEGER NOT NULL,
            previous_signature_sha256 TEXT,
            signed_at TEXT NOT NULL,
            manifest_expires_at TEXT NOT NULL,
            note TEXT NOT NULL,
            hashes_json TEXT NOT NULL,
            signature TEXT NOT NULL,
            base_signature_sha256 TEXT,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
        """
    )
    connection.execute("DELETE FROM manifest_objects")
    manifest_rows = connection.execute("SELECT public_key,hashes_json FROM manifests").fetchall()
    for public_key, hashes_json in manifest_rows:
        try:
            hashes = normalize_hashes(json.loads(hashes_json))
        except (ValueError, TypeError, json.JSONDecodeError):
            continue
        connection.executemany(
            "INSERT OR IGNORE INTO manifest_objects(public_key,object_hash) VALUES(?,?)",
            ((public_key, object_hash) for object_hash in hashes),
        )
    connection.execute("PRAGMA foreign_keys=ON")
    connection.commit()
    connection.close()


# -----------------------------------------------------------------------------
# Encoding, validation, and canonicalization helpers
# -----------------------------------------------------------------------------

def create_json_error_response(message: str, status: int = 400, **extra: Any) -> tuple[Response, int]:
    """Build a consistent JSON error response."""
    return jsonify(error=message, **extra), status


def base64url_decode(value: str) -> bytes:
    """Decode unpadded Base64URL text into bytes."""
    padded = value + "=" * ((4 - len(value) % 4) % 4)  # Restore omitted Base64 padding.
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def base64url_encode(value: bytes) -> str:
    """Encode bytes as canonical unpadded Base64URL text."""
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def normalize_public_key(value: Any) -> tuple[str, bytes]:
    """Validate and canonicalize a 32-byte Ed25519 public key."""
    text = str(value or "").strip()  # Accept either prefixed or raw Base64URL input.
    if not text.startswith(PUBLIC_KEY_PREFIX):
        text = PUBLIC_KEY_PREFIX + text
    match = PUBLIC_KEY_PATTERN.fullmatch(text)
    if not match:
        raise ValueError("Public key must be a 32-byte Ed25519 key.")
    try:
        public_key_bytes = base64url_decode(match.group(1))
    except (ValueError, binascii.Error) as error:
        raise ValueError("Public key encoding is invalid.") from error
    if len(public_key_bytes) != 32:
        raise ValueError("Ed25519 public key must contain exactly 32 bytes.")
    return PUBLIC_KEY_PREFIX + base64url_encode(public_key_bytes), public_key_bytes


def normalize_hashes(values: Any) -> list[str]:
    """Return a sorted, deduplicated, canonical SHA-256 hash list."""
    if not isinstance(values, list):
        raise ValueError("Hashes must be a JSON array.")
    hashes = sorted({str(value).strip().lower() for value in values})  # Sorting and deduplication make signatures deterministic.
    if not hashes:
        raise ValueError("At least one video hash is required.")
    if len(hashes) > MAX_MANIFEST_FILES:
        raise ValueError(f"A manifest may contain at most {MAX_MANIFEST_FILES} hashes.")
    if any(not HASH_PATTERN.fullmatch(value) for value in hashes):
        raise ValueError("Every manifest entry must be a lowercase SHA-256 value.")
    return hashes


def normalize_signature(value: Any) -> str:
    """Validate and canonicalize a detached 64-byte Ed25519 signature."""
    text = str(value or "").strip()
    if not SIGNATURE_PATTERN.fullmatch(text):
        raise ValueError("Signature must be a 64-byte Ed25519 detached signature.")
    try:
        signature_bytes = base64url_decode(text)
    except (ValueError, binascii.Error) as error:
        raise ValueError("Signature encoding is invalid.") from error
    if len(signature_bytes) != 64:
        raise ValueError("Ed25519 signature must contain exactly 64 bytes.")
    return base64url_encode(signature_bytes)


def normalize_revision(value: Any) -> int:
    """Require a positive integer manifest revision without ambiguous coercion."""
    if isinstance(value, bool):
        raise ValueError("Manifest revision must be a positive integer.")
    try:
        revision = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError("Manifest revision must be a positive integer.") from error
    if revision < 1 or str(value).strip() != str(revision):
        raise ValueError("Manifest revision must be a positive integer.")
    return revision


def normalize_previous_signature_sha256(value: Any, revision: int) -> str | None:
    """Validate the signed link to the immediately previous manifest signature."""
    if revision == 1:
        if value not in (None, ""):
            raise ValueError("Revision 1 cannot reference a previous signature.")
        return None
    normalized = str(value or "").strip().lower()
    if not HASH_PATTERN.fullmatch(normalized):
        raise ValueError("A later revision must reference the previous signature SHA-256.")
    return normalized


def normalize_manifest_timestamp(value: Any, label: str) -> tuple[str, datetime]:
    """Validate one signed ISO 8601 timestamp with an explicit timezone offset."""
    text = str(value or "").strip()
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})", text):
        raise ValueError(f"{label} must be an ISO 8601 timestamp with a timezone offset.")
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{label} is invalid.") from error
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError(f"{label} must include a timezone offset.")
    return text, moment


def normalize_manifest_metadata(signed_at: Any, expires_at: Any, note: Any) -> tuple[str, str, str, datetime, datetime]:
    """Canonicalize signed time metadata and verify the deterministic signed note."""
    signed_text, signed_moment = normalize_manifest_timestamp(signed_at, "Signed time")
    expires_text, expires_moment = normalize_manifest_timestamp(expires_at, "Expiration time")
    if expires_moment <= signed_moment:
        raise ValueError("Expiration time must be later than signed time.")
    expected_note = f"Signed at {signed_text}; expires at {expires_text}."
    normalized_note = str(note or "").strip()
    if normalized_note != expected_note:
        raise ValueError("Manifest note must exactly describe its signed and expiration times.")
    return signed_text, expires_text, normalized_note, signed_moment, expires_moment


# -----------------------------------------------------------------------------
# Video metadata and content-addressed storage helpers
# -----------------------------------------------------------------------------

def normalize_video_extension(file_name: str, mime_type: str) -> str:
    """Select a safe video extension from the upload name or MIME type."""
    allowed_extensions = {".mp4", ".m4v", ".mov", ".webm", ".mkv", ".avi", ".ogv", ".ogg", ".flv", ".mpg", ".mpeg", ".3gp", ".ts"}
    suffix = Path(file_name or "").suffix.lower()
    if suffix in allowed_extensions:
        return suffix
    mime_extension = mimetypes.guess_extension((mime_type or "").split(";", 1)[0].strip()) or ""
    return mime_extension.lower() if mime_extension.lower() in allowed_extensions else ""


def sniff_video_metadata(path: Path, stored_mime_type: str | None = None, stored_extension: str | None = None) -> tuple[str, str]:
    """Infer a conservative download MIME type and extension from file signatures."""
    mime_type = str(stored_mime_type or "").strip().lower()
    extension = str(stored_extension or "").strip().lower()
    if extension and not extension.startswith("."):
        extension = "." + extension
    try:
        with path.open("rb") as source:
            header = source.read(64)
    except OSError:
        header = b""
    if len(header) >= 12 and header[4:8] == b"ftyp":
        brand = header[8:12].lower()
        if brand.startswith(b"3g"):
            return "video/3gpp", ".3gp"
        if brand in {b"qt  "}:
            return "video/quicktime", ".mov"
        if brand in {b"m4v ", b"m4vh", b"m4vp"}:
            return "video/x-m4v", ".m4v"
        return "video/mp4", ".mp4"
    if header.startswith(b"\x1aE\xdf\xa3"):
        if b"webm" in header.lower():
            return "video/webm", ".webm"
        return "video/x-matroska", ".mkv"
    if header.startswith(b"RIFF") and header[8:12] == b"AVI ":
        return "video/x-msvideo", ".avi"
    if header.startswith(b"OggS"):
        return "video/ogg", ".ogv"
    if header.startswith(b"FLV"):
        return "video/x-flv", ".flv"
    if header[:4] in {b"\x00\x00\x01\xba", b"\x00\x00\x01\xb3"}:
        return "video/mpeg", ".mpg"
    if mime_type.startswith("video/") and extension:
        return mime_type, extension
    if mime_type.startswith("video/"):
        guessed = mimetypes.guess_extension(mime_type) or ""
        return mime_type, guessed if guessed else ".video"
    if extension:
        return mimetypes.guess_type("file" + extension)[0] or "application/octet-stream", extension
    return "application/octet-stream", ".bin"


# -----------------------------------------------------------------------------
# Signed-manifest construction and Ed25519 verification
# -----------------------------------------------------------------------------

def build_manifest_message(
    public_key: str,
    revision: int,
    previous_signature_sha256: str | None,
    hashes: list[str],
    signed_at: str | None = None,
    expires_at: str | None = None,
    note: str | None = None,
) -> bytes:
    """Serialize every signed field into one deterministic UTF-8 JSON message."""
    canonical: dict[str, Any] = {
        "public_key": public_key,
        "revision": revision,
        "previous_signature_sha256": previous_signature_sha256,
    }
    has_temporal_fields = any(value not in (None, "") for value in (signed_at, expires_at, note))
    if has_temporal_fields:
        signed_text, expires_text, normalized_note, _, _ = normalize_manifest_metadata(signed_at, expires_at, note)
        canonical.update(signed_at=signed_text, expires_at=expires_text, note=normalized_note)
    canonical["hashes"] = hashes  # Every individual video hash remains directly covered by the signature.
    return json.dumps(canonical, ensure_ascii=False, separators=(",", ":")).encode("utf-8")  # Compact JSON is the exact signed byte sequence.


def signature_sha256(signature_text: str) -> str:
    """Hash the raw detached signature for revision-chain linking."""
    return hashlib.sha256(base64url_decode(signature_text)).hexdigest()


def verify_manifest_signature(public_key_bytes: bytes, message: bytes, signature_text: str) -> bool:
    """Verify one canonical manifest message with its Ed25519 public key."""
    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(base64url_decode(signature_text), message)
        return True
    except (InvalidSignature, ValueError, binascii.Error):
        return False


def calculate_file_sha256(path: Path) -> str:
    """Calculate a file SHA-256 incrementally without loading it into memory."""
    calculator = hashlib.sha256()  # Incremental hashing supports very large videos.
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(4 * 1024 * 1024), b""):
            calculator.update(chunk)
    return calculator.hexdigest()


def get_object_storage_path(object_hash: str) -> Path:
    """Map a canonical SHA-256 address to its content-addressed storage path."""
    return OBJECT_DIRECTORY / object_hash


# -----------------------------------------------------------------------------
# Stored-object and persisted-manifest verification
# -----------------------------------------------------------------------------

def get_object_integrity_statuses(hashes: list[str]) -> dict[str, dict[str, Any]]:
    """Return existence, integrity, MIME, and extension status for signed objects."""
    connection = get_database()
    metadata: dict[str, sqlite3.Row] = {}
    for offset in range(0, len(hashes), 500):
        batch = hashes[offset:offset + 500]
        placeholders = ",".join("?" for _ in batch)
        for row in connection.execute(f"SELECT * FROM objects WHERE hash IN ({placeholders})", batch).fetchall():
            metadata[row["hash"]] = row

    def inspect(value: str) -> tuple[str, dict[str, Any]]:
        row = metadata.get(value)
        path = Path(row["path"]) if row is not None else get_object_storage_path(value)
        exists = path.is_file()
        valid = exists and (calculate_file_sha256(path) == value if VERIFY_OBJECTS_ON_SEARCH else True)  # Never trust a database row as proof of file integrity.
        mime_type, extension = sniff_video_metadata(
            path,
            row["mime_type"] if row is not None and "mime_type" in row.keys() else None,
            row["extension"] if row is not None and "extension" in row.keys() else None,
        ) if exists else ("application/octet-stream", "")
        return value, {
            "hash": value,
            "exists": exists,
            "valid": valid,
            "mime_type": mime_type,
            "extension": extension,
            "download_name": value + extension if extension else value,
        }

    with ThreadPoolExecutor(max_workers=INTEGRITY_WORKERS) as executor:
        return dict(executor.map(inspect, hashes))


def serialize_manifest_row(row: sqlite3.Row, include_objects: bool = False) -> dict[str, Any]:
    """Convert one verified SQLite row into the public manifest representation."""
    revision = normalize_revision(row["revision"])
    previous_signature_sha256 = normalize_previous_signature_sha256(row["previous_signature_sha256"], revision)
    hashes = normalize_hashes(json.loads(row["hashes_json"]))
    manifest: dict[str, Any] = {
        "public_key": row["public_key"],
        "revision": revision,
        "previous_signature_sha256": previous_signature_sha256,
        "hashes": hashes,
        "signature": row["signature"],
    }
    signed_at = row["signed_at"] if "signed_at" in row.keys() else None
    expires_at = row["expires_at"] if "expires_at" in row.keys() else None
    note = row["note"] if "note" in row.keys() else None
    if any(value not in (None, "") for value in (signed_at, expires_at, note)):
        signed_text, expires_text, normalized_note, _, expires_moment = normalize_manifest_metadata(signed_at, expires_at, note)
        manifest.update(
            signed_at=signed_text,
            expires_at=expires_text,
            note=normalized_note,
            expired=expires_moment <= datetime.now(timezone.utc),
        )
    else:
        manifest["legacy"] = True
    if include_objects:
        statuses = get_object_integrity_statuses(hashes)
        manifest["objects"] = [statuses[value] for value in hashes]
    return manifest


def verify_stored_manifest(row: sqlite3.Row) -> bool:
    """Reconstruct and verify a stored manifest instead of trusting database flags."""
    try:
        public_key, public_key_bytes = normalize_public_key(row["public_key"])
        revision = normalize_revision(row["revision"])
        previous_signature_sha256 = normalize_previous_signature_sha256(row["previous_signature_sha256"], revision)
        hashes = normalize_hashes(json.loads(row["hashes_json"]))
        signature = normalize_signature(row["signature"])
        signed_at = row["signed_at"] if "signed_at" in row.keys() else None
        expires_at = row["expires_at"] if "expires_at" in row.keys() else None
        note = row["note"] if "note" in row.keys() else None
        message = build_manifest_message(public_key, revision, previous_signature_sha256, hashes, signed_at, expires_at, note)
        return verify_manifest_signature(public_key_bytes, message, signature)
    except (ValueError, TypeError, json.JSONDecodeError):
        return False


def get_current_manifest_state(connection: sqlite3.Connection, public_key: str) -> tuple[int, str | None, sqlite3.Row | None]:
    """Return the current revision and signature hash for optimistic replacement."""
    row = connection.execute("SELECT * FROM manifests WHERE public_key=?", (public_key,)).fetchone()
    if row is None:
        return 0, None, None
    if not verify_stored_manifest(row):
        raise ValueError("The stored current manifest failed Ed25519 verification.")
    return int(row["revision"]), signature_sha256(row["signature"]), row


def cleanup_expired_pending_publications(connection: sqlite3.Connection) -> None:
    """Remove abandoned two-phase publication records after their expiry time."""
    connection.execute("DELETE FROM pending_publications WHERE expires_at < ?", (format_utc_timestamp(),))
    connection.commit()


# -----------------------------------------------------------------------------
# Page rendering and HTTP routes
# -----------------------------------------------------------------------------

def render_page(title: str, active_page: str, content: str, page_javascript: str = "") -> str:
    """Render one embedded page with shared styles and cryptographic scripts."""
    return render_template_string(
        BASE_TEMPLATE,
        title=title,
        active_page=active_page,
        content=content,
        page_javascript=page_javascript,
        theme_css=THEME_CSS,
        common_javascript=COMMON_JAVASCRIPT,
        bootstrap_css_url=BOOTSTRAP_CSS_URL,
        bootstrap_js_url=BOOTSTRAP_JS_URL,
        tweetnacl_url=TWEETNACL_URL,
        js_sha256_url=JS_SHA256_URL,
        source_code_url=SOURCE_CODE_URL,
    )


@application.errorhandler(RequestEntityTooLarge)
def upload_too_large(_: RequestEntityTooLarge) -> tuple[Response, int]:
    """Return a JSON HTTP 413 response for oversized object uploads."""
    return create_json_error_response("The request exceeds MAX_UPLOAD_BYTES.", 413)


@application.get("/")
def home_page() -> str:
    """Render the project overview page."""
    return render_page("Home", "home", HOME_CONTENT)


@application.get("/identity")
def identity_page() -> str:
    """Render the local Ed25519 identity generation page."""
    return render_page("Identity", "identity", IDENTITY_CONTENT, IDENTITY_JAVASCRIPT)


@application.get("/publish")
def publish_page() -> str:
    """Render the sequential hashing and two-phase publication page."""
    return render_page("Publish", "publish", PUBLISH_CONTENT, PUBLISH_JAVASCRIPT)


@application.get("/search")
def search_page() -> str:
    """Render the public-key and SHA-256 search page."""
    return render_page("Search", "search", SEARCH_CONTENT, SEARCH_JAVASCRIPT)


@application.get("/api/status")
def api_status() -> Response:
    """Expose non-secret runtime limits and protocol capabilities."""
    return jsonify(
        service="digital-signature-hash-video-platform",
        signature="Ed25519",
        content_address="SHA-256",
        publication="two-phase-ajax-versioned-current-manifest",
    )


@application.get("/api/manifest-state")
def manifest_state() -> tuple[Response, int] | Response:
    """Return the current revision chain head for a public key."""
    try:
        public_key, _ = normalize_public_key(request.args.get("public_key"))
        revision, current_signature_sha256, _ = get_current_manifest_state(get_database(), public_key)
    except ValueError as error:
        return create_json_error_response(str(error), 409)
    return jsonify(public_key=public_key, current_revision=revision, current_signature_sha256=current_signature_sha256, server_time=format_utc_timestamp())


@application.post("/api/publish/prepare")
def prepare_publication() -> tuple[Response, int] | Response:
    """Verify a signed manifest before issuing a temporary object-upload token."""
    payload = request.get_json(silent=True) or {}
    try:
        public_key, public_key_bytes = normalize_public_key(payload.get("public_key"))
        revision = normalize_revision(payload.get("revision"))
        previous_signature_sha256 = normalize_previous_signature_sha256(payload.get("previous_signature_sha256"), revision)
        signed_at, manifest_expires_at, note, signed_moment, expires_moment = normalize_manifest_metadata(payload.get("signed_at"), payload.get("expires_at"), payload.get("note"))
        hashes = normalize_hashes(payload.get("hashes"))
        signature = normalize_signature(payload.get("signature"))
    except ValueError as error:
        return create_json_error_response(str(error))
    message = build_manifest_message(public_key, revision, previous_signature_sha256, hashes, signed_at, manifest_expires_at, note)
    now = datetime.now(timezone.utc)
    if signed_moment > now + timedelta(minutes=15):
        return create_json_error_response("Signed time is too far in the future.", 409)
    if expires_moment <= now:
        return create_json_error_response("Manifest expiration time has already passed.", 409)
    if not verify_manifest_signature(public_key_bytes, message, signature):
        return create_json_error_response("Ed25519 manifest signature verification failed.", 403)
    connection = get_database()
    cleanup_expired_pending_publications(connection)
    try:
        current_revision, current_signature_sha256, _ = get_current_manifest_state(connection, public_key)
    except ValueError as error:
        return create_json_error_response(str(error), 409)
    if revision != current_revision + 1 or previous_signature_sha256 != current_signature_sha256:
        return create_json_error_response(
            "The signed revision is stale or does not extend the current manifest.",
            409,
            current_revision=current_revision,
            current_signature_sha256=current_signature_sha256,
        )
    statuses = get_object_integrity_statuses(hashes)
    missing_hashes = [value for value in hashes if not statuses[value]["exists"] or not statuses[value]["valid"]]
    reused_hashes = [value for value in hashes if value not in missing_hashes]
    token = secrets.token_urlsafe(32)  # Unpredictable token binds later uploads to this verified manifest.
    created_at = datetime.now(timezone.utc)
    expires_at = created_at + timedelta(minutes=PENDING_LIFETIME_MINUTES)
    connection.execute(
        "INSERT INTO pending_publications(token,public_key,revision,previous_signature_sha256,signed_at,manifest_expires_at,note,hashes_json,signature,base_signature_sha256,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            token,
            public_key,
            revision,
            previous_signature_sha256,
            signed_at,
            manifest_expires_at,
            note,
            json.dumps(hashes, separators=(",", ":")),
            signature,
            current_signature_sha256,
            format_utc_timestamp(created_at),
            format_utc_timestamp(expires_at),
        ),
    )
    connection.commit()
    return jsonify(
        token=token,
        signature_valid=True,
        revision=revision,
        missing_hashes=missing_hashes,
        reused_hashes=reused_hashes,
    )


@application.post("/api/publish/upload/<token>/<object_hash>")
def upload_pending_object(token: str, object_hash: str) -> tuple[Response, int] | Response:
    """Accept one missing video only when its bytes match a preverified signed hash."""
    object_hash = object_hash.lower()
    if not HASH_PATTERN.fullmatch(object_hash):
        return create_json_error_response("Object hash is invalid.")
    connection = get_database()
    cleanup_expired_pending_publications(connection)
    pending = connection.execute("SELECT * FROM pending_publications WHERE token=?", (token,)).fetchone()
    if pending is None:
        return create_json_error_response("Publication token is invalid or expired.", 404)
    hashes = normalize_hashes(json.loads(pending["hashes_json"]))
    if object_hash not in hashes:
        return create_json_error_response("This object hash is not part of the signed pending manifest.", 403)
    video = request.files.get("video")
    if video is None:
        return create_json_error_response("Video file is missing.")
    descriptor, temporary_name = tempfile.mkstemp(prefix="upload-", dir=TEMPORARY_DIRECTORY)
    os.close(descriptor)
    temporary_path = Path(temporary_name)
    calculator = hashlib.sha256()
    size = 0
    try:
        with temporary_path.open("wb") as destination:
            while True:
                chunk = video.stream.read(4 * 1024 * 1024)
                if not chunk:
                    break
                destination.write(chunk)
                calculator.update(chunk)
                size += len(chunk)
        actual_hash = calculator.hexdigest()  # Server-side recomputation rejects mismatched or substituted bytes.
        if actual_hash != object_hash:
            return create_json_error_response("Uploaded video SHA-256 does not match the signed hash.", 409, actual_hash=actual_hash)
        destination_path = get_object_storage_path(object_hash)
        with OBJECT_STORAGE_LOCK:
            if destination_path.exists() and calculate_file_sha256(destination_path) == object_hash:
                temporary_path.unlink(missing_ok=True)
                reused = True
            else:
                os.replace(temporary_path, destination_path)
                reused = False
            mime_type = (video.mimetype or "application/octet-stream").split(";", 1)[0].strip().lower()
            extension = normalize_video_extension(video.filename or "", mime_type)
            detected_mime_type, detected_extension = sniff_video_metadata(destination_path, mime_type, extension)
            connection.execute(
                "INSERT INTO objects(hash,size,path,created_at,mime_type,extension) VALUES(?,?,?,?,?,?) "
                "ON CONFLICT(hash) DO UPDATE SET size=excluded.size,path=excluded.path,mime_type=excluded.mime_type,extension=excluded.extension",
                (object_hash, size, str(destination_path), format_utc_timestamp(), detected_mime_type, detected_extension),
            )
            connection.commit()
        return jsonify(hash=object_hash, reused=reused)
    finally:
        temporary_path.unlink(missing_ok=True)


@application.post("/api/publish/finalize")
def finalize_publication() -> tuple[Response, int] | Response:
    """Atomically replace the public key current manifest after all objects verify."""
    payload = request.get_json(silent=True) or {}
    token = str(payload.get("token") or "").strip()
    if not token:
        return create_json_error_response("Publication token is required.")
    connection = get_database()
    cleanup_expired_pending_publications(connection)
    pending = connection.execute("SELECT * FROM pending_publications WHERE token=?", (token,)).fetchone()
    if pending is None:
        return create_json_error_response("Publication token is invalid or expired.", 404)
    try:
        public_key, public_key_bytes = normalize_public_key(pending["public_key"])
        revision = normalize_revision(pending["revision"])
        previous_signature_sha256 = normalize_previous_signature_sha256(pending["previous_signature_sha256"], revision)
        signed_at, manifest_expires_at, note, _, expires_moment = normalize_manifest_metadata(pending["signed_at"], pending["manifest_expires_at"], pending["note"])
        hashes = normalize_hashes(json.loads(pending["hashes_json"]))
        signature = normalize_signature(pending["signature"])
    except (ValueError, json.JSONDecodeError) as error:
        return create_json_error_response(str(error), 409)
    message = build_manifest_message(public_key, revision, previous_signature_sha256, hashes, signed_at, manifest_expires_at, note)
    if expires_moment <= datetime.now(timezone.utc):
        return create_json_error_response("The signed manifest expired before publication was finalized.", 409)
    if not verify_manifest_signature(public_key_bytes, message, signature):
        return create_json_error_response("Pending manifest signature verification failed.", 409)
    statuses = get_object_integrity_statuses(hashes)
    invalid_hashes = [value for value in hashes if not statuses[value]["exists"] or not statuses[value]["valid"]]
    if invalid_hashes:
        return create_json_error_response("Not every signed video object is present and valid.", 409, invalid_hashes=invalid_hashes)
    timestamp = format_utc_timestamp()
    try:
        connection.execute("BEGIN IMMEDIATE")  # Serialize the final revision check and manifest replacement.
        current_revision, current_signature_sha256, _ = get_current_manifest_state(connection, public_key)
        if (
            revision != current_revision + 1
            or previous_signature_sha256 != current_signature_sha256
            or pending["base_signature_sha256"] != current_signature_sha256
        ):
            connection.rollback()
            return create_json_error_response(
                "The current manifest changed while this publication was uploading. Recalculate and sign again.",
                409,
                current_revision=current_revision,
                current_signature_sha256=current_signature_sha256,
            )
        connection.execute(
            "INSERT INTO manifests(public_key,revision,previous_signature_sha256,signed_at,expires_at,note,hashes_json,signature,updated_at) VALUES(?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(public_key) DO UPDATE SET revision=excluded.revision,previous_signature_sha256=excluded.previous_signature_sha256,signed_at=excluded.signed_at,expires_at=excluded.expires_at,note=excluded.note,hashes_json=excluded.hashes_json,signature=excluded.signature,updated_at=excluded.updated_at",
            (public_key, revision, previous_signature_sha256, signed_at, manifest_expires_at, note, json.dumps(hashes, separators=(",", ":")), signature, timestamp),
        )
        connection.execute("DELETE FROM manifest_objects WHERE public_key=?", (public_key,))
        connection.executemany("INSERT INTO manifest_objects(public_key,object_hash) VALUES(?,?)", ((public_key, value) for value in hashes))
        connection.execute("DELETE FROM pending_publications WHERE token=?", (token,))
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    row = connection.execute("SELECT * FROM manifests WHERE public_key=?", (public_key,)).fetchone()
    return jsonify(manifest=serialize_manifest_row(row))


@application.get("/api/search")
def search_manifests() -> tuple[Response, int] | Response:
    """Search current manifests by exact public key or contained video SHA-256."""
    query = str(request.args.get("q") or "").strip()
    if not query:
        return create_json_error_response("Search query is required.")
    connection = get_database()
    if HASH_PATTERN.fullmatch(query.lower()):
        object_hash = query.lower()
        rows = connection.execute(
            "SELECT m.* FROM manifests m JOIN manifest_objects mo ON mo.public_key=m.public_key WHERE mo.object_hash=? ORDER BY m.updated_at DESC",
            (object_hash,),
        ).fetchall()
        rows = [row for row in rows if verify_stored_manifest(row) and object_hash in normalize_hashes(json.loads(row["hashes_json"]))]
    else:
        try:
            public_key, _ = normalize_public_key(query)
        except ValueError as error:
            return create_json_error_response(str(error))
        row = connection.execute("SELECT * FROM manifests WHERE public_key=?", (public_key,)).fetchone()
        rows = [row] if row is not None and verify_stored_manifest(row) else []
    return jsonify(manifests=[serialize_manifest_row(row, include_objects=True) for row in rows])


@application.get("/object/<object_hash>")
def download_object(object_hash: str) -> tuple[Response, int] | Response:
    """Rehash and return one content-addressed object with a safe extension."""
    object_hash = object_hash.lower()
    if not HASH_PATTERN.fullmatch(object_hash):
        return create_json_error_response("Object hash is invalid.")
    row = get_database().execute("SELECT * FROM objects WHERE hash=?", (object_hash,)).fetchone()
    if row is None:
        return create_json_error_response("The requested video object does not exist.", 404)
    path = Path(row["path"])
    if not path.is_file():
        return create_json_error_response("The requested video object is missing.", 410)
    if calculate_file_sha256(path) != object_hash:
        return create_json_error_response("The stored video object failed SHA-256 verification.", 409)
    mime_type, extension = sniff_video_metadata(
        path,
        row["mime_type"] if "mime_type" in row.keys() else None,
        row["extension"] if "extension" in row.keys() else None,
    )
    download_name = object_hash + extension
    response = send_file(path, mimetype=mime_type, as_attachment=True, download_name=download_name, conditional=True, etag=object_hash)
    response.headers["X-Content-SHA256"] = object_hash  # Let clients compare the advertised content address.
    response.headers["X-Download-Filename"] = download_name
    response.headers["Cache-Control"] = "public, immutable, max-age=31536000"
    return response


# -----------------------------------------------------------------------------
# Application initialization and development server entry point
# -----------------------------------------------------------------------------

initialize_database()

if __name__ == "__main__":
    ssl_context: str | None = "adhoc" if DEVELOPMENT_TLS == "adhoc" else None
    application.run(host=DEVELOPMENT_HOST, port=DEVELOPMENT_PORT, threaded=True, ssl_context=ssl_context)
