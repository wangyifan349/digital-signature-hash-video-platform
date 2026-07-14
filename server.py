"""Digital Signature Hash Video Platform.

This single-file Flask server embeds the complete frontend and backend.
It provides account-free Ed25519 identities, atomic publication of complete
video collections, SHA-256 content-addressed storage, public-key or file-hash
search, and browser-side verification before downloaded bytes are saved.

The private key never leaves the browser. One Ed25519 signature covers the
literal newline-delimited list of every SHA-256 file hash; the application does
not replace that list with a combined collection hash. The server verifies the
signature and independently recalculates every uploaded video hash before the
collection becomes visible.
"""

# SPDX-License-Identifier: AGPL-3.0-or-later

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from flask import Flask, g, jsonify, render_template_string, request, send_file
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from markupsafe import Markup
import base64
import binascii
import hashlib
import json
import os
import re
import secrets
import shutil
import sqlite3
import tempfile

BASE_DIRECTORY = Path(__file__).resolve().parent  # Project root.
DATABASE_PATH = Path(os.environ.get("DATABASE_PATH", BASE_DIRECTORY / "digital_signature_hash_video_platform.db"))  # SQLite database.
OBJECT_DIRECTORY = Path(os.environ.get("OBJECT_DIRECTORY", BASE_DIRECTORY / "video_objects"))  # SHA-256 object storage.
TEMPORARY_DIRECTORY = Path(os.environ.get("TEMPORARY_DIRECTORY", BASE_DIRECTORY / "temporary_uploads"))  # Atomic upload staging.
SOURCE_CODE_URL = os.environ.get("SOURCE_CODE_URL", "https://github.com/wangyifan349/digital-signature-hash-video-platform")  # AGPL source URL.
MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", 32 * 1024 * 1024 * 1024))  # Maximum complete request size.
MAX_COLLECTION_FILES = max(1, int(os.environ.get("MAX_COLLECTION_FILES", "10000")))  # Maximum videos in one collection.
VERIFY_OBJECTS_ON_SEARCH = os.environ.get("VERIFY_OBJECTS_ON_SEARCH", "1") == "1"  # Rehash stored objects during search.
INTEGRITY_WORKER_COUNT = max(1, int(os.environ.get("INTEGRITY_WORKERS", min(4, os.cpu_count() or 1))))  # Parallel hash workers.
DEVELOPMENT_HOST = os.environ.get("HOST", "0.0.0.0")  # Development bind address.
DEVELOPMENT_PORT = int(os.environ.get("PORT", "5000"))  # Development port.
DEVELOPMENT_TLS_MODE = os.environ.get("DEVELOPMENT_TLS", "adhoc").strip().lower()  # Ad-hoc HTTPS by default.

HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")  # Canonical SHA-256 hexadecimal value.
PUBLIC_KEY_PATTERN = re.compile(r"^ed25519:([A-Za-z0-9_-]{43})$")  # Raw 32-byte Ed25519 public key.
PRIVATE_KEY_PATTERN = re.compile(r"^ed25519-private:([A-Za-z0-9_-]{43})$")  # Browser private-seed format.
COLLECTION_PROTOCOL = "digital-signature-hash-video-list-v5"  # Signed-list protocol identifier.
COLLECTION_SIGNATURE_PREFIX = "DIGITAL-SIGNATURE-HASH-VIDEO-LIST-V5"  # Signature domain separator.
OBJECT_STORAGE_LOCK = RLock()  # Protect same-process object replacement.

OBJECT_DIRECTORY.mkdir(parents=True, exist_ok=True)
TEMPORARY_DIRECTORY.mkdir(parents=True, exist_ok=True)

application = Flask(__name__)  # Main WSGI application.
application.config.update(MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES, SEND_FILE_MAX_AGE_DEFAULT=31536000)
app = application  # Conventional Flask alias.

THEME_CSS = r"""/* Project-defined RGB colors intentionally use a zero blue channel. */
:root{--page-background:#160900;--navigation-background:#7a2200;--surface-background:#2a1200;--surface-raised:#351800;--surface-soft:#4a2000;--primary-color:#ff4d00;--primary-dark:#a52f00;--accent-color:#ffad00;--text-color:#ffd900;--muted-text:#c18400;--border-color:#7a3800;--success-color:#00a000;--danger-color:#d00000;--warning-color:#d89000;--black-color:#000000;--shadow-color:rgba(0,0,0,.28);--focus-color:rgba(255,77,0,.28);--bs-body-color:var(--text-color);--bs-body-bg:var(--page-background);--bs-secondary-color:var(--muted-text);--bs-border-color:var(--border-color);--bs-link-color:var(--accent-color);--bs-link-hover-color:var(--primary-color)}
html{background:var(--page-background)}body{min-height:100vh;background:var(--page-background);color:var(--text-color)}a{color:var(--accent-color)}a:hover{color:var(--primary-color)}
.navbar{background:var(--navigation-background);border-bottom:1px solid var(--primary-color);box-shadow:0 .2rem .55rem var(--shadow-color)}.navbar .container{padding-top:.18rem!important;padding-bottom:.18rem!important}.navbar-brand{color:var(--text-color)!important;font-size:.94rem;line-height:1.02}.navbar-brand small{color:var(--muted-text);font-size:.66rem}.navbar .nav-link{color:var(--muted-text);font-size:.88rem;padding:.25rem .55rem}.navbar .nav-link:hover,.navbar .nav-link.active{color:var(--text-color)}.brand-mark{width:1.85rem;height:1.85rem;display:grid;place-items:center;border-radius:.38rem;background:var(--primary-color);color:var(--black-color);font-weight:900}
.card,.hero-panel{background:var(--surface-background);color:var(--text-color);border:1px solid var(--border-color);border-radius:.85rem;box-shadow:0 .5rem 1.25rem var(--shadow-color)}.card-header{background:var(--surface-raised);color:var(--text-color);border-bottom:1px solid var(--border-color);font-weight:750}.section-note{border-left:.3rem solid var(--primary-color);background:var(--surface-raised);color:var(--text-color)}.feature-icon{width:2.6rem;height:2.6rem;display:grid;place-items:center;border-radius:.7rem;background:var(--surface-soft);color:var(--accent-color);font-weight:800}.page-heading{max-width:820px}.small-muted,.text-secondary{color:var(--muted-text)!important}.text-success{color:var(--success-color)!important}.text-danger{color:var(--danger-color)!important}.text-warning{color:var(--warning-color)!important}.status{white-space:pre-wrap;min-height:1.4rem}.monospace{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;word-break:break-all}.hash-entry{border:1px solid var(--border-color);border-radius:.75rem;background:var(--surface-raised)}.hash-link{color:var(--accent-color);font-weight:700;text-decoration:none}.hash-link:hover{color:var(--primary-color);text-decoration:underline}.identity-empty,.drop-zone{border:1px dashed var(--border-color);border-radius:.75rem;background:var(--surface-raised);padding:1rem}.sticky-panel{position:sticky;top:.75rem}
.form-control,.form-select{background:var(--surface-raised);border-color:var(--border-color);color:var(--text-color)}.form-control::placeholder{color:var(--muted-text)}.form-control:focus,.form-select:focus{background:var(--surface-raised);border-color:var(--primary-color);color:var(--text-color);box-shadow:0 0 0 .2rem var(--focus-color)}.form-control[readonly]{background:var(--surface-soft);color:var(--text-color)}
.btn-theme{--bs-btn-color:var(--black-color);--bs-btn-bg:var(--primary-color);--bs-btn-border-color:var(--primary-color);--bs-btn-hover-color:var(--black-color);--bs-btn-hover-bg:var(--accent-color);--bs-btn-hover-border-color:var(--accent-color);--bs-btn-active-color:var(--text-color);--bs-btn-active-bg:var(--primary-dark);--bs-btn-active-border-color:var(--primary-dark)}.btn-outline-theme{--bs-btn-color:var(--accent-color);--bs-btn-border-color:var(--primary-color);--bs-btn-hover-color:var(--black-color);--bs-btn-hover-bg:var(--primary-color);--bs-btn-hover-border-color:var(--primary-color)}.btn-outline-danger{--bs-btn-color:var(--danger-color);--bs-btn-border-color:var(--danger-color);--bs-btn-hover-color:var(--text-color);--bs-btn-hover-bg:var(--danger-color);--bs-btn-hover-border-color:var(--danger-color)}.btn-link{--bs-btn-color:var(--accent-color);--bs-btn-hover-color:var(--primary-color)}
.alert{background:var(--surface-raised);color:var(--text-color);border-color:var(--border-color)}.progress{background:var(--surface-raised);border:1px solid var(--border-color)}.progress-bar{background:var(--primary-color)}.badge-valid{background:var(--success-color)!important;color:var(--black-color)!important}.badge-invalid{background:var(--danger-color)!important;color:var(--text-color)!important}.badge-neutral{background:var(--surface-soft)!important;color:var(--text-color)!important}.badge-warning-custom{background:var(--warning-color)!important;color:var(--black-color)!important}footer{color:var(--muted-text)!important}hr{border-color:var(--border-color);opacity:1}
@media(max-width:991.98px){.sticky-panel{position:static}}@media(max-width:767.98px){.navbar-brand small{display:none}.navbar .container{align-items:flex-start}}"""

CRYPTO_JAVASCRIPT = r"""/**
 * Bundled SHA-256, SHA-512, and Ed25519 implementation used by the browser.
 * Cryptographic formulas retain conventional short mathematical symbols where
 * renaming them would obscure correspondence with the published algorithms.
 * Hashing and signatures use the bundled implementation; getRandomValues supplies entropy only.
 */
(function(global){
"use strict";
const MASK_64=(1n<<64n)-1n;
const SHA512_INITIAL=[0x6a09e667f3bcc908n,0xbb67ae8584caa73bn,0x3c6ef372fe94f82bn,0xa54ff53a5f1d36f1n,0x510e527fade682d1n,0x9b05688c2b3e6c1fn,0x1f83d9abfb41bd6bn,0x5be0cd19137e2179n];
const SHA512_CONSTANTS=[0x428a2f98d728ae22n,0x7137449123ef65cdn,0xb5c0fbcfec4d3b2fn,0xe9b5dba58189dbbcn,0x3956c25bf348b538n,0x59f111f1b605d019n,0x923f82a4af194f9bn,0xab1c5ed5da6d8118n,0xd807aa98a3030242n,0x12835b0145706fben,0x243185be4ee4b28cn,0x550c7dc3d5ffb4e2n,0x72be5d74f27b896fn,0x80deb1fe3b1696b1n,0x9bdc06a725c71235n,0xc19bf174cf692694n,0xe49b69c19ef14ad2n,0xefbe4786384f25e3n,0x0fc19dc68b8cd5b5n,0x240ca1cc77ac9c65n,0x2de92c6f592b0275n,0x4a7484aa6ea6e483n,0x5cb0a9dcbd41fbd4n,0x76f988da831153b5n,0x983e5152ee66dfabn,0xa831c66d2db43210n,0xb00327c898fb213fn,0xbf597fc7beef0ee4n,0xc6e00bf33da88fc2n,0xd5a79147930aa725n,0x06ca6351e003826fn,0x142929670a0e6e70n,0x27b70a8546d22ffcn,0x2e1b21385c26c926n,0x4d2c6dfc5ac42aedn,0x53380d139d95b3dfn,0x650a73548baf63den,0x766a0abb3c77b2a8n,0x81c2c92e47edaee6n,0x92722c851482353bn,0xa2bfe8a14cf10364n,0xa81a664bbc423001n,0xc24b8b70d0f89791n,0xc76c51a30654be30n,0xd192e819d6ef5218n,0xd69906245565a910n,0xf40e35855771202an,0x106aa07032bbd1b8n,0x19a4c116b8d2d0c8n,0x1e376c085141ab53n,0x2748774cdf8eeb99n,0x34b0bcb5e19b48a8n,0x391c0cb3c5c95a63n,0x4ed8aa4ae3418acbn,0x5b9cca4f7763e373n,0x682e6ff3d6b2b8a3n,0x748f82ee5defb2fcn,0x78a5636f43172f60n,0x84c87814a1f0ab72n,0x8cc702081a6439ecn,0x90befffa23631e28n,0xa4506cebde82bde9n,0xbef9a3f7b2c67915n,0xc67178f2e372532bn,0xca273eceea26619cn,0xd186b8c721c0c207n,0xeada7dd6cde0eb1en,0xf57d4f7fee6ed178n,0x06f067aa72176fban,0x0a637dc5a2c898a6n,0x113f9804bef90daen,0x1b710b35131c471bn,0x28db77f523047d84n,0x32caab7b40c72493n,0x3c9ebe0a15c9bebcn,0x431d67c49c100d4cn,0x4cc5d4becb3e42b6n,0x597f299cfc657e2an,0x5fcb6fab3ad6faecn,0x6c44198c4a475817n];
const ED25519_P=(1n<<255n)-19n;
const ED25519_L=(1n<<252n)+27742317777372353535851937790883648493n;
function mod(value,modulus=ED25519_P){const result=value%modulus;return result>=0n?result:result+modulus;}
function modPow(base,exponent,modulus=ED25519_P){let result=1n;let value=mod(base,modulus);let power=exponent;while(power>0n){if(power&1n)result=result*value%modulus;value=value*value%modulus;power>>=1n;}return result;}
function invert(value){if(value===0n)throw new Error("Division by zero");return modPow(value,ED25519_P-2n);}
const ED25519_D=mod(-121665n*invert(121666n));
const ED25519_I=modPow(2n,(ED25519_P-1n)/4n);
function bytesToBigIntLE(bytes){let value=0n;for(let index=bytes.length-1;index>=0;index--)value=(value<<8n)+BigInt(bytes[index]);return value;}
function bigIntToBytesLE(value,length){let output=new Uint8Array(length);let current=value;for(let index=0;index<length;index++){output[index]=Number(current&255n);current>>=8n;}return output;}
function concatenateBytes(...arrays){const length=arrays.reduce((total,array)=>total+array.length,0);const output=new Uint8Array(length);let offset=0;for(const array of arrays){output.set(array,offset);offset+=array.length;}return output;}
function bytesToHex(bytes){return Array.from(bytes,value=>value.toString(16).padStart(2,"0")).join("");}
function hexToBytes(value){if(typeof value!=="string"||value.length%2)throw new Error("Invalid hexadecimal value");const output=new Uint8Array(value.length/2);for(let index=0;index<output.length;index++){const byte=Number.parseInt(value.slice(index*2,index*2+2),16);if(Number.isNaN(byte))throw new Error("Invalid hexadecimal value");output[index]=byte;}return output;}
function bytesToBase64Url(bytes){let binary="";for(let offset=0;offset<bytes.length;offset+=32768)binary+=String.fromCharCode(...bytes.subarray(offset,offset+32768));return btoa(binary).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");}
function base64UrlToBytes(value){if(typeof value!=="string")throw new Error("Invalid base64url value");let normalized=value.replace(/-/g,"+").replace(/_/g,"/");while(normalized.length%4)normalized+="=";let binary;try{binary=atob(normalized);}catch{throw new Error("Invalid base64url value");}const output=new Uint8Array(binary.length);for(let index=0;index<binary.length;index++)output[index]=binary.charCodeAt(index);return output;}
function rotr64(value,shift){const amount=BigInt(shift);return ((value>>amount)|(value<<(64n-amount)))&MASK_64;}
function sha512(message){const input=message instanceof Uint8Array?message:new Uint8Array(message);const totalLength=Math.ceil((input.length+17)/128)*128;const padded=new Uint8Array(totalLength);padded.set(input);padded[input.length]=128;const bitLength=BigInt(input.length)*8n;for(let index=0;index<16;index++)padded[totalLength-1-index]=Number((bitLength>>BigInt(index*8))&255n);const state=SHA512_INITIAL.slice();const words=new Array(80).fill(0n);for(let offset=0;offset<totalLength;offset+=128){for(let index=0;index<16;index++){let value=0n;for(let byteIndex=0;byteIndex<8;byteIndex++)value=(value<<8n)+BigInt(padded[offset+index*8+byteIndex]);words[index]=value;}for(let index=16;index<80;index++){const s0=rotr64(words[index-15],1)^rotr64(words[index-15],8)^(words[index-15]>>7n);const s1=rotr64(words[index-2],19)^rotr64(words[index-2],61)^(words[index-2]>>6n);words[index]=(words[index-16]+s0+words[index-7]+s1)&MASK_64;}let [a,b,c,d,e,f,g,h]=state;for(let index=0;index<80;index++){const sum1=rotr64(e,14)^rotr64(e,18)^rotr64(e,41);const choose=(e&f)^(((~e)&MASK_64)&g);const temporary1=(h+sum1+choose+SHA512_CONSTANTS[index]+words[index])&MASK_64;const sum0=rotr64(a,28)^rotr64(a,34)^rotr64(a,39);const majority=(a&b)^(a&c)^(b&c);const temporary2=(sum0+majority)&MASK_64;h=g;g=f;f=e;e=(d+temporary1)&MASK_64;d=c;c=b;b=a;a=(temporary1+temporary2)&MASK_64;}state[0]=(state[0]+a)&MASK_64;state[1]=(state[1]+b)&MASK_64;state[2]=(state[2]+c)&MASK_64;state[3]=(state[3]+d)&MASK_64;state[4]=(state[4]+e)&MASK_64;state[5]=(state[5]+f)&MASK_64;state[6]=(state[6]+g)&MASK_64;state[7]=(state[7]+h)&MASK_64;}const output=new Uint8Array(64);for(let index=0;index<8;index++){for(let byteIndex=0;byteIndex<8;byteIndex++)output[index*8+byteIndex]=Number((state[index]>>BigInt((7-byteIndex)*8))&255n);}return output;}
const SHA256_CONSTANTS=new Uint32Array([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
class Sha256{constructor(){this.state=new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);this.buffer=new Uint8Array(64);this.bufferLength=0;this.bytesHashed=0;this.words=new Uint32Array(64);this.finished=false;}rotate(value,count){return (value>>>count)|(value<<(32-count));}processBlock(chunk,offset){const words=this.words;for(let index=0;index<16;index++){const position=offset+index*4;words[index]=((chunk[position]<<24)|(chunk[position+1]<<16)|(chunk[position+2]<<8)|chunk[position+3])>>>0;}for(let index=16;index<64;index++){const previous15=words[index-15],previous2=words[index-2];const sigma0=this.rotate(previous15,7)^this.rotate(previous15,18)^(previous15>>>3);const sigma1=this.rotate(previous2,17)^this.rotate(previous2,19)^(previous2>>>10);words[index]=(words[index-16]+sigma0+words[index-7]+sigma1)>>>0;}let [a,b,c,d,e,f,g,h]=this.state;for(let index=0;index<64;index++){const sigma1=this.rotate(e,6)^this.rotate(e,11)^this.rotate(e,25);const choose=(e&f)^(~e&g);const temporary1=(h+sigma1+choose+SHA256_CONSTANTS[index]+words[index])>>>0;const sigma0=this.rotate(a,2)^this.rotate(a,13)^this.rotate(a,22);const majority=(a&b)^(a&c)^(b&c);const temporary2=(sigma0+majority)>>>0;h=g;g=f;f=e;e=(d+temporary1)>>>0;d=c;c=b;b=a;a=(temporary1+temporary2)>>>0;}this.state[0]=(this.state[0]+a)>>>0;this.state[1]=(this.state[1]+b)>>>0;this.state[2]=(this.state[2]+c)>>>0;this.state[3]=(this.state[3]+d)>>>0;this.state[4]=(this.state[4]+e)>>>0;this.state[5]=(this.state[5]+f)>>>0;this.state[6]=(this.state[6]+g)>>>0;this.state[7]=(this.state[7]+h)>>>0;}update(data){if(this.finished)throw new Error("SHA-256 hash is already finalized");const input=data instanceof Uint8Array?data:new Uint8Array(data);let position=0;this.bytesHashed+=input.length;while(position<input.length){const count=Math.min(64-this.bufferLength,input.length-position);this.buffer.set(input.subarray(position,position+count),this.bufferLength);this.bufferLength+=count;position+=count;if(this.bufferLength===64){this.processBlock(this.buffer,0);this.bufferLength=0;}}return this;}digest(){if(this.finished)throw new Error("SHA-256 hash is already finalized");const bitLength=BigInt(this.bytesHashed)*8n;this.buffer[this.bufferLength++]=128;if(this.bufferLength>56){this.buffer.fill(0,this.bufferLength);this.processBlock(this.buffer,0);this.bufferLength=0;}this.buffer.fill(0,this.bufferLength,56);for(let index=0;index<8;index++)this.buffer[63-index]=Number((bitLength>>BigInt(index*8))&255n);this.processBlock(this.buffer,0);this.finished=true;const output=new Uint8Array(32);for(let index=0;index<8;index++){output[index*4]=this.state[index]>>>24;output[index*4+1]=this.state[index]>>>16;output[index*4+2]=this.state[index]>>>8;output[index*4+3]=this.state[index];}return output;}digestHex(){return bytesToHex(this.digest());}}
function sha256(message){return new Sha256().update(message).digest();}
function recoverX(y,sign){const ySquared=mod(y*y);const numerator=mod(ySquared-1n);const denominator=mod(ED25519_D*ySquared+1n);const xSquared=mod(numerator*invert(denominator));let x=modPow(xSquared,(ED25519_P+3n)/8n);if(mod(x*x-xSquared)!==0n)x=mod(x*ED25519_I);if(mod(x*x-xSquared)!==0n)throw new Error("Invalid Ed25519 point");if(Number(x&1n)!==sign)x=ED25519_P-x;if(x===0n&&sign===1)throw new Error("Invalid Ed25519 point sign");return x;}
function pointFromAffine(x,y){return {X:mod(x),Y:mod(y),Z:1n,T:mod(x*y)};}
const BASE_Y=mod(4n*invert(5n));
const BASE_POINT=pointFromAffine(recoverX(BASE_Y,0),BASE_Y);
const IDENTITY_POINT={X:0n,Y:1n,Z:1n,T:0n};
function pointAdd(first,second){const a=mod((first.Y-first.X)*(second.Y-second.X));const b=mod((first.Y+first.X)*(second.Y+second.X));const c=mod(2n*ED25519_D*first.T*second.T);const d=mod(2n*first.Z*second.Z);const e=mod(b-a);const f=mod(d-c);const g=mod(d+c);const h=mod(b+a);return {X:mod(e*f),Y:mod(g*h),T:mod(e*h),Z:mod(f*g)};}
function pointDouble(point){const a=mod(point.X*point.X);const b=mod(point.Y*point.Y);const c=mod(2n*point.Z*point.Z);const d=mod(-a);const e=mod((point.X+point.Y)*(point.X+point.Y)-a-b);const g=mod(d+b);const f=mod(g-c);const h=mod(d-b);return {X:mod(e*f),Y:mod(g*h),T:mod(e*h),Z:mod(f*g)};}
function scalarMultiply(point,scalar){let result=IDENTITY_POINT;let addend=point;let value=scalar;while(value>0n){if(value&1n)result=pointAdd(result,addend);addend=pointDouble(addend);value>>=1n;}return result;}
function encodePoint(point){const inverseZ=invert(point.Z);const x=mod(point.X*inverseZ);const y=mod(point.Y*inverseZ);const output=bigIntToBytesLE(y,32);output[31]|=Number((x&1n)<<7n);return output;}
function decodePoint(bytes){if(!(bytes instanceof Uint8Array)||bytes.length!==32)throw new Error("Invalid Ed25519 point length");const encoded=new Uint8Array(bytes);const sign=encoded[31]>>>7;encoded[31]&=127;const y=bytesToBigIntLE(encoded);if(y>=ED25519_P)throw new Error("Invalid Ed25519 point encoding");return pointFromAffine(recoverX(y,sign),y);}
function pointsEqual(first,second){return mod(first.X*second.Z-second.X*first.Z)===0n&&mod(first.Y*second.Z-second.Y*first.Z)===0n;}
function privateScalarAndPrefix(seed){if(!(seed instanceof Uint8Array)||seed.length!==32)throw new Error("Ed25519 seed must contain exactly 32 bytes");const digest=sha512(seed);const scalarBytes=digest.slice(0,32);scalarBytes[0]&=248;scalarBytes[31]&=63;scalarBytes[31]|=64;return {scalar:bytesToBigIntLE(scalarBytes),prefix:digest.slice(32)};}
function keyPairFromSeed(seed){const material=privateScalarAndPrefix(seed);const publicKey=encodePoint(scalarMultiply(BASE_POINT,material.scalar));return {publicKey,seed:new Uint8Array(seed)};}
function sign(message,seed){const input=message instanceof Uint8Array?message:new Uint8Array(message);const material=privateScalarAndPrefix(seed);const publicKey=encodePoint(scalarMultiply(BASE_POINT,material.scalar));const nonce=bytesToBigIntLE(sha512(concatenateBytes(material.prefix,input)))%ED25519_L;const encodedR=encodePoint(scalarMultiply(BASE_POINT,nonce));const challenge=bytesToBigIntLE(sha512(concatenateBytes(encodedR,publicKey,input)))%ED25519_L;const s=mod(nonce+challenge*material.scalar,ED25519_L);return concatenateBytes(encodedR,bigIntToBytesLE(s,32));}
function verify(message,signature,publicKey){try{const input=message instanceof Uint8Array?message:new Uint8Array(message);if(!(signature instanceof Uint8Array)||signature.length!==64||!(publicKey instanceof Uint8Array)||publicKey.length!==32)return false;const encodedR=signature.slice(0,32);const s=bytesToBigIntLE(signature.slice(32));if(s>=ED25519_L)return false;const publicPoint=decodePoint(publicKey);const rPoint=decodePoint(encodedR);const challenge=bytesToBigIntLE(sha512(concatenateBytes(encodedR,publicKey,input)))%ED25519_L;const left=scalarMultiply(BASE_POINT,s);const right=pointAdd(rPoint,scalarMultiply(publicPoint,challenge));return pointsEqual(left,right);}catch{return false;}}
function secureRandomBytes(length){const provider=(typeof global.crypto!=="undefined"&&global.crypto)||(typeof global.msCrypto!=="undefined"&&global.msCrypto);if(!provider||typeof provider.getRandomValues!=="function")throw new Error("A cryptographically secure random-number generator is required");const output=new Uint8Array(length);provider.getRandomValues(output);return output;}
function generateKeyPair(){const seed=secureRandomBytes(32);const pair=keyPairFromSeed(seed);return {seed:pair.seed,publicKey:pair.publicKey};}
function selfTest(){const seed=hexToBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");const expectedPublic="d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";const expectedSignature="e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";const pair=keyPairFromSeed(seed);const signature=sign(new Uint8Array(0),seed);if(bytesToHex(pair.publicKey)!==expectedPublic||bytesToHex(signature)!==expectedSignature||!verify(new Uint8Array(0),signature,pair.publicKey))throw new Error("Embedded Ed25519 self-test failed");const abc=new TextEncoder().encode("abc");if(bytesToHex(sha256(abc))!=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")throw new Error("Embedded SHA-256 self-test failed");if(bytesToHex(sha512(abc))!=="ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")throw new Error("Embedded SHA-512 self-test failed");return true;}
global.DshvpCrypto={Sha256,sha256,sha512,bytesToHex,hexToBytes,bytesToBase64Url,base64UrlToBytes,concatenateBytes,ed25519:{generateKeyPair,keyPairFromSeed,sign,verify},selfTest};
})(typeof globalThis!=="undefined"?globalThis:this);
"""

COMMON_JAVASCRIPT = r""""use strict";
const App={
    element(identifier){return document.getElementById(identifier);},
    encoder:new TextEncoder(),
    hashPattern:/^[0-9a-f]{64}$/,
    publicKeyPattern:/^ed25519:[A-Za-z0-9_-]{43}$/,
    privateKeyPattern:/^ed25519-private:[A-Za-z0-9_-]{43}$/,
    setStatus(identifier,message,state="secondary"){
        const target=this.element(identifier);
        target.textContent=message;
        target.className=`status small mt-2 text-${state}`;
    },
    escapeHtml(value){return String(value).replace(/[&<>"']/g,character=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[character]));},
    normalizePublicKey(publicKeyText){
        const value=String(publicKeyText||"").trim();
        if(!this.publicKeyPattern.test(value))throw new Error("Public key must use ed25519:<base64url> format.");
        const publicKeyBytes=DshvpCrypto.base64UrlToBytes(value.slice("ed25519:".length));
        if(publicKeyBytes.length!==32)throw new Error("Ed25519 public key must contain exactly 32 bytes.");
        return {text:`ed25519:${DshvpCrypto.bytesToBase64Url(publicKeyBytes)}`,bytes:publicKeyBytes};
    },
    parsePrivateKey(privateKeyText){
        let value=String(privateKeyText||"").trim();
        if(!value)throw new Error("Enter or import an Ed25519 private key.");
        if(value.startsWith("{")){
            const privateKeyRecord=JSON.parse(value);
            value=privateKeyRecord.private_key||privateKeyRecord.private_seed||"";
        }
        if(!value.startsWith("ed25519-private:"))value=`ed25519-private:${value}`;
        if(!this.privateKeyPattern.test(value))throw new Error("Private key must contain a 32-byte Ed25519 seed.");
        const privateSeed=DshvpCrypto.base64UrlToBytes(value.slice("ed25519-private:".length));
        if(privateSeed.length!==32)throw new Error("Ed25519 private seed must contain exactly 32 bytes.");
        const keyPair=DshvpCrypto.ed25519.keyPairFromSeed(privateSeed);
        return {privateSeed,privateKey:`ed25519-private:${DshvpCrypto.bytesToBase64Url(privateSeed)}`,publicKey:`ed25519:${DshvpCrypto.bytesToBase64Url(keyPair.publicKey)}`,publicKeyBytes:keyPair.publicKey};
    },
    buildSignatureMessage(publicKey,hashes){
        const normalizedPublicKey=this.normalizePublicKey(publicKey).text;
        const canonicalHashes=[...hashes].map(value=>String(value).toLowerCase());
        if(!canonicalHashes.length)throw new Error("At least one SHA-256 hash is required.");
        if(canonicalHashes.some(value=>!this.hashPattern.test(value)))throw new Error("The hash list contains an invalid SHA-256 value.");
        if(canonicalHashes.join("\n")!==[...new Set(canonicalHashes)].sort().join("\n"))throw new Error("Hashes must be unique and sorted.");
        return `DIGITAL-SIGNATURE-HASH-VIDEO-LIST-V5\nPUBLIC-KEY ${normalizedPublicKey}\n${canonicalHashes.map(value=>`HASH ${value}`).join("\n")}`;
    },
    signHashList(identity,hashes){
        const message=this.encoder.encode(this.buildSignatureMessage(identity.publicKey,hashes));
        const signature=DshvpCrypto.ed25519.sign(message,identity.privateSeed);
        return DshvpCrypto.bytesToBase64Url(signature);
    },
    verifyHashList(publicKey,hashes,signatureText){
        const normalizedPublicKey=this.normalizePublicKey(publicKey);
        const signature=DshvpCrypto.base64UrlToBytes(signatureText);
        if(signature.length!==64)return false;
        return DshvpCrypto.ed25519.verify(this.encoder.encode(this.buildSignatureMessage(normalizedPublicKey.text,hashes)),signature,normalizedPublicKey.bytes);
    },
    async hashFile(file,progressCallback){
        const hashCalculator=new DshvpCrypto.Sha256();
        const chunkSize=4*1024*1024;
        for(let offset=0;offset<file.size;offset+=chunkSize){
            const chunk=new Uint8Array(await file.slice(offset,offset+chunkSize).arrayBuffer());
            hashCalculator.update(chunk);
            if(progressCallback)progressCallback(Math.min(1,(offset+chunk.length)/Math.max(file.size,1)));
            await new Promise(resolve=>setTimeout(resolve,0));
        }
        return hashCalculator.digestHex();
    },
    async requestJson(url,options={}){
        options.headers=options.headers||{};
        if(options.body&&!(options.body instanceof FormData))options.headers["Content-Type"]="application/json";
        const response=await fetch(url,options);
        const payload=await response.json().catch(()=>({error:"The server returned an invalid response."}));
        if(!response.ok)throw new Error(payload.error||`HTTP ${response.status}`);
        return payload;
    },
    downloadTextFile(fileName,text){
        const blob=new Blob([text],{type:"application/json"});
        const link=document.createElement("a");
        link.href=URL.createObjectURL(blob);
        link.download=fileName;
        link.click();
        URL.revokeObjectURL(link.href);
    },
    async verifiedDownload(objectHash,statusIdentifier="searchStatus"){
        this.setStatus(statusIdentifier,`Downloading and verifying ${objectHash}…`,"secondary");
        const response=await fetch(`/object/${objectHash}`);
        if(!response.ok){
            const payload=await response.json().catch(()=>({error:"Download failed."}));
            throw new Error(payload.error||"Download failed.");
        }
        const reader=response.body.getReader();
        const hashCalculator=new DshvpCrypto.Sha256();
        const chunks=[];
        let receivedBytes=0;
        while(true){
            const result=await reader.read();
            if(result.done)break;
            hashCalculator.update(result.value);
            chunks.push(result.value);
            receivedBytes+=result.value.length;
            this.setStatus(statusIdentifier,`Downloaded ${receivedBytes.toLocaleString()} bytes; recalculating SHA-256…`,"secondary");
        }
        const calculatedHash=hashCalculator.digestHex();
        if(calculatedHash!==objectHash)throw new Error(`Downloaded bytes failed SHA-256 verification. Actual hash: ${calculatedHash}`);
        const downloadBlob=new Blob(chunks,{type:"application/octet-stream"});
        const downloadLink=document.createElement("a");
        downloadLink.href=URL.createObjectURL(downloadBlob);
        downloadLink.download=`${objectHash}.video`;
        downloadLink.click();
        URL.revokeObjectURL(downloadLink.href);
        this.setStatus(statusIdentifier,"Download completed. Browser-side SHA-256 verification passed.","success");
    }
};
window.DshvpApp=App;
window.addEventListener("DOMContentLoaded",()=>{
    try{DshvpCrypto.selfTest();}
    catch(error){document.body.innerHTML=`<main class="container py-5"><div class="alert">Embedded cryptography self-test failed: ${App.escapeHtml(error.message)}</div></main>`;}
});"""

IDENTITY_JAVASCRIPT = r""""use strict";
let generatedIdentity=null;
function renderGeneratedIdentity(){
    const summary=DshvpApp.element("generatedIdentitySummary");
    const actions=DshvpApp.element("generatedIdentityActions");
    if(!generatedIdentity){summary.textContent="No identity has been generated.";actions.classList.add("d-none");return;}
    summary.textContent="A new Ed25519 identity exists only in this browser page memory. Save the private key before leaving.";
    actions.classList.remove("d-none");
    DshvpApp.element("privateKeyOutput").value=generatedIdentity.privateKey;
    DshvpApp.element("publicKeyOutput").value=generatedIdentity.publicKey;
}
function generateIdentity(){
    try{
        const keyPair=DshvpCrypto.ed25519.generateKeyPair();
        generatedIdentity={privateSeed:keyPair.seed,privateKey:`ed25519-private:${DshvpCrypto.bytesToBase64Url(keyPair.seed)}`,publicKey:`ed25519:${DshvpCrypto.bytesToBase64Url(keyPair.publicKey)}`};
        renderGeneratedIdentity();
        DshvpApp.setStatus("identityStatus","Ed25519 identity generated locally. Nothing was sent to the server.","success");
    }catch(error){DshvpApp.setStatus("identityStatus",error.message,"danger");}
}
function downloadPrivateKey(){
    if(!generatedIdentity)return;
    const keyRecord={format:"digital-signature-hash-video-private-key-v1",algorithm:"Ed25519",private_key:generatedIdentity.privateKey,public_key:generatedIdentity.publicKey,warning:"Possession of this private key permits signatures for this public identity."};
    DshvpApp.downloadTextFile("ed25519-private-key.json",JSON.stringify(keyRecord,null,2));
}
async function copyPrivateKey(){
    if(!generatedIdentity)return;
    await navigator.clipboard.writeText(generatedIdentity.privateKey);
    DshvpApp.setStatus("identityStatus","Private key copied. Protect it from disclosure.","success");
}
async function copyPublicKey(){
    if(!generatedIdentity)return;
    await navigator.clipboard.writeText(generatedIdentity.publicKey);
    DshvpApp.setStatus("identityStatus","Public key copied. Other users can search with this value.","success");
}
window.addEventListener("DOMContentLoaded",()=>{
    DshvpApp.element("generateIdentityButton").onclick=generateIdentity;
    DshvpApp.element("downloadPrivateKeyButton").onclick=downloadPrivateKey;
    DshvpApp.element("copyPrivateKeyButton").onclick=copyPrivateKey;
    DshvpApp.element("copyPublicKeyButton").onclick=copyPublicKey;
});"""

PUBLISH_JAVASCRIPT = r""""use strict";
let publisherIdentity=null;
let preparedPublication=null;
let preparationSequence=0;
function renderPublisherIdentity(){
    DshvpApp.element("derivedPublicKey").value=publisherIdentity?publisherIdentity.publicKey:"";
    DshvpApp.element("videoFiles").disabled=!publisherIdentity;
    DshvpApp.element("publishCollectionButton").disabled=!preparedPublication;
}
function loadPrivateKeyAutomatically(){
    try{
        publisherIdentity=DshvpApp.parsePrivateKey(DshvpApp.element("privateKeyInput").value);
        DshvpApp.setStatus("privateKeyStatus","Private key loaded in page memory. The public key was derived automatically.","success");
    }catch(error){
        publisherIdentity=null;
        preparedPublication=null;
        if(DshvpApp.element("privateKeyInput").value.trim())DshvpApp.setStatus("privateKeyStatus",error.message,"danger");
        else DshvpApp.setStatus("privateKeyStatus","Enter or import a private key. It is never uploaded.","secondary");
    }
    renderPublisherIdentity();
    if(publisherIdentity&&DshvpApp.element("videoFiles").files.length)preparePublicationAutomatically();
}
async function importPrivateKeyFile(file){
    DshvpApp.element("privateKeyInput").value=await file.text();
    loadPrivateKeyAutomatically();
}
async function preparePublicationAutomatically(){
    const sequence=++preparationSequence;
    preparedPublication=null;
    renderPublisherIdentity();
    if(!publisherIdentity)return;
    const selectedFiles=Array.from(DshvpApp.element("videoFiles").files);
    if(!selectedFiles.length){DshvpApp.setStatus("publicationStatus","Select the complete set of videos for this public key.","secondary");return;}
    try{
        DshvpApp.setStatus("publicationStatus",`Calculating SHA-256 for ${selectedFiles.length} video(s)…`,"secondary");
        const hashRecords=[];
        for(let fileIndex=0;fileIndex<selectedFiles.length;fileIndex++){
            const selectedFile=selectedFiles[fileIndex];
            const objectHash=await DshvpApp.hashFile(selectedFile,fileProgress=>{
                const overallProgress=(fileIndex+fileProgress)/selectedFiles.length;
                DshvpApp.element("publicationProgressBar").style.width=`${Math.round(overallProgress*70)}%`;
            });
            hashRecords.push({hash:objectHash,file:selectedFile,size:selectedFile.size});
            if(sequence!==preparationSequence)return;
        }
        hashRecords.sort((leftRecord,rightRecord)=>leftRecord.hash.localeCompare(rightRecord.hash));
        const hashes=hashRecords.map(hashRecord=>hashRecord.hash);
        if(new Set(hashes).size!==hashes.length)throw new Error("Duplicate video bytes are not allowed in one signed collection.");
        const signature=DshvpApp.signHashList(publisherIdentity,hashes);
        preparedPublication={records:hashRecords,hashes,signature,publicKey:publisherIdentity.publicKey};
        renderPreparedPublication();
        DshvpApp.element("publicationProgressBar").style.width="70%";
        DshvpApp.setStatus("publicationStatus",`Ready. One Ed25519 signature directly covers ${hashes.length} individual SHA-256 hash line(s). No combined collection hash is used.`,"success");
    }catch(error){DshvpApp.setStatus("publicationStatus",error.message,"danger");}
    renderPublisherIdentity();
}
function renderPreparedPublication(){
    const preview=DshvpApp.element("collectionPreview");
    if(!preparedPublication){preview.innerHTML='<div class="small-muted">No signed hash list prepared.</div>';DshvpApp.element("signatureOutput").value="";return;}
    preview.innerHTML=preparedPublication.records.map((record,index)=>`<div class="hash-entry p-3"><span class="badge badge-neutral me-2">${index+1}</span><span class="monospace">${record.hash}</span><div class="small-muted mt-1">${record.size.toLocaleString()} bytes · original filename ignored</div></div>`).join("");
    DshvpApp.element("signatureOutput").value=preparedPublication.signature;
}
async function uploadPreparedPublication(){
    if(!preparedPublication)throw new Error("Select all videos and wait for hashing and signing to complete.");
    DshvpApp.element("publishCollectionButton").disabled=true;
    DshvpApp.setStatus("publicationStatus","Uploading the complete signed collection in one request…","secondary");
    const formData=new FormData();
    formData.append("public_key",preparedPublication.publicKey);
    formData.append("hashes",JSON.stringify(preparedPublication.hashes));
    formData.append("signature",preparedPublication.signature);
    preparedPublication.records.forEach(record=>formData.append("videos",record.file,record.hash));
    const result=await new Promise((resolve,reject)=>{
        const requestObject=new XMLHttpRequest();
        requestObject.open("POST","/api/collections");
        requestObject.upload.onprogress=progressEvent=>{
            if(progressEvent.lengthComputable)DshvpApp.element("publicationProgressBar").style.width=`${70+Math.round(progressEvent.loaded/progressEvent.total*30)}%`;
        };
        requestObject.onload=()=>{
            let payload;
            try{payload=JSON.parse(requestObject.responseText);}catch{reject(new Error("The server returned an invalid response."));return;}
            if(requestObject.status<300)resolve(payload);else reject(new Error(payload.error||`HTTP ${requestObject.status}`));
        };
        requestObject.onerror=()=>reject(new Error("Network upload failed."));
        requestObject.send(formData);
    });
    DshvpApp.element("publicationProgressBar").style.width="100%";
    const receipt={format:"digital-signature-hash-video-receipt-v1",protocol:"digital-signature-hash-video-list-v5",public_key:preparedPublication.publicKey,hashes:preparedPublication.hashes,signature:preparedPublication.signature,server_received_at:result.created_at};
    DshvpApp.downloadTextFile("signed-video-hash-list-receipt.json",JSON.stringify(receipt,null,2));
    DshvpApp.setStatus("publicationStatus",`Published ${result.object_count} video(s). The server verified the Ed25519 signature and independently recalculated every SHA-256 hash. A signed receipt was downloaded.`,"success");
}
window.addEventListener("DOMContentLoaded",()=>{
    let privateKeyTimer=null;
    DshvpApp.element("privateKeyInput").oninput=()=>{clearTimeout(privateKeyTimer);privateKeyTimer=setTimeout(loadPrivateKeyAutomatically,180);};
    DshvpApp.element("importPrivateKeyButton").onclick=()=>DshvpApp.element("privateKeyFileInput").click();
    DshvpApp.element("privateKeyFileInput").onchange=async event=>{
        const selectedFile=event.target.files[0];
        if(selectedFile)await importPrivateKeyFile(selectedFile);
        event.target.value="";
    };
    DshvpApp.element("videoFiles").onchange=preparePublicationAutomatically;
    DshvpApp.element("publishCollectionButton").onclick=async()=>{
        try{await uploadPreparedPublication();}
        catch(error){DshvpApp.setStatus("publicationStatus",error.message,"danger");DshvpApp.element("publishCollectionButton").disabled=false;}
    };
    renderPreparedPublication();
    renderPublisherIdentity();
});"""

SEARCH_JAVASCRIPT = r""""use strict";
function objectBadges(objectRecord){
    const availability=objectRecord.object_available?'<span class="badge badge-valid">Object available</span>':'<span class="badge badge-invalid">Object unavailable</span>';
    const integrity=objectRecord.object_integrity===true?'<span class="badge badge-valid">Server SHA-256 valid</span>':objectRecord.object_integrity===false?'<span class="badge badge-invalid">Server hash mismatch</span>':'<span class="badge badge-neutral">Integrity not prechecked</span>';
    return `${availability}${integrity}`;
}
function bindHashDownloads(){
    document.querySelectorAll("[data-download-hash]").forEach(downloadButton=>{
        downloadButton.onclick=async()=>{
            try{await DshvpApp.verifiedDownload(downloadButton.dataset.downloadHash);}
            catch(error){DshvpApp.setStatus("searchStatus",error.message,"danger");}
        };
    });
}
function bindPublicKeySearches(){
    document.querySelectorAll("[data-public-key]").forEach(publicKeyButton=>{
        publicKeyButton.onclick=()=>{
            DshvpApp.element("searchInput").value=publicKeyButton.dataset.publicKey;
            performSearch();
        };
    });
}
function renderPublicKeyResult(result){
    const signatureValid=DshvpApp.verifyHashList(result.public_key,result.hashes,result.signature);
    if(!signatureValid)throw new Error("Browser-side Ed25519 verification failed. The returned hash list must not be trusted.");
    const objectByHash=new Map(result.objects.map(objectRecord=>[objectRecord.hash,objectRecord]));
    DshvpApp.element("searchResults").innerHTML=`<div class="section-note rounded-3 p-3"><div><strong>Public key</strong></div><div class="monospace">${DshvpApp.escapeHtml(result.public_key)}</div><div class="mt-2"><span class="badge badge-valid">Ed25519 signature valid</span><span class="badge badge-neutral">${result.hashes.length} signed hashes</span></div></div>${result.hashes.map(objectHash=>{const objectRecord=objectByHash.get(objectHash)||{object_available:false,object_integrity:null,size:null};const downloadControl=objectRecord.object_available?`<button class="btn btn-link p-0 text-start hash-link monospace" data-download-hash="${objectHash}">${objectHash}</button>`:`<span class="monospace">${objectHash}</span>`;return `<div class="hash-entry p-3"><div class="d-flex flex-wrap gap-2 mb-2">${objectBadges(objectRecord)}</div>${downloadControl}<div class="small-muted mt-1">${objectRecord.size===null||objectRecord.size===undefined?"unknown":Number(objectRecord.size).toLocaleString()} bytes</div></div>`;}).join("")}`;
    bindHashDownloads();
    DshvpApp.setStatus("searchStatus",`Verified ${result.hashes.length} signed video hash(es) for this public key.`,"success");
}
function renderHashResult(result){
    const downloadControl=result.object_available?`<button class="btn btn-link p-0 text-start hash-link monospace" data-download-hash="${result.hash}">${result.hash}</button>`:`<span class="monospace">${result.hash}</span>`;
    const publicKeys=result.public_keys.length?result.public_keys.map(publicKey=>`<button class="btn btn-link p-0 text-start monospace d-block" data-public-key="${DshvpApp.escapeHtml(publicKey)}">${DshvpApp.escapeHtml(publicKey)}</button>`).join(""):'<div class="small-muted">No signed public-key collection references this hash.</div>';
    DshvpApp.element("searchResults").innerHTML=`<div class="hash-entry p-3"><div class="d-flex flex-wrap gap-2 mb-2">${objectBadges(result)}</div>${downloadControl}<div class="small-muted mt-3">Public keys whose valid signed lists contain this hash:</div>${publicKeys}</div>`;
    bindHashDownloads();
    bindPublicKeySearches();
    DshvpApp.setStatus("searchStatus",`Hash lookup completed. ${result.public_keys.length} public key(s) reference this video hash.`,"success");
}
async function performSearch(){
    const query=DshvpApp.element("searchInput").value.trim();
    DshvpApp.element("searchResults").innerHTML="";
    try{
        DshvpApp.setStatus("searchStatus","Retrieving and verifying cryptographic records…","secondary");
        const result=await DshvpApp.requestJson("/api/search",{method:"POST",body:JSON.stringify({query})});
        if(result.type==="public_key")renderPublicKeyResult(result);else renderHashResult(result);
    }catch(error){DshvpApp.setStatus("searchStatus",error.message,"danger");}
}
window.addEventListener("DOMContentLoaded",()=>{
    DshvpApp.element("searchButton").onclick=performSearch;
    DshvpApp.element("searchInput").onkeydown=keyboardEvent=>{if(keyboardEvent.key==="Enter"&&!keyboardEvent.shiftKey){keyboardEvent.preventDefault();performSearch();}};
});"""

PAGE_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ page_title }} · Digital Signature Hash Video Platform</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<style nonce="{{ csp_nonce }}">{{ theme_css }}</style>
<script nonce="{{ csp_nonce }}">{{ crypto_javascript }}</script>
<script nonce="{{ csp_nonce }}">{{ common_javascript }}</script>
<script nonce="{{ csp_nonce }}">{{ page_javascript }}</script>
</head>
<body>
<nav class="navbar mb-4"><div class="container d-flex flex-wrap align-items-center gap-2"><a class="navbar-brand d-flex align-items-center gap-2 me-auto" href="/"><span class="brand-mark">D</span><span><strong>Digital Signature Hash Video Platform</strong><small class="d-block">Ed25519 signed hash lists · SHA-256 video objects</small></span></a><div class="d-flex flex-wrap align-items-center gap-1"><a class="nav-link {% if active_page=='home' %}active{% endif %}" href="/">Home</a><a class="nav-link {% if active_page=='identity' %}active{% endif %}" href="/identity">Identity</a><a class="nav-link {% if active_page=='publish' %}active{% endif %}" href="/publish">Publish</a><a class="nav-link {% if active_page=='search' %}active{% endif %}" href="/search">Search</a></div></div></nav>
<main class="container pb-5">{{ page_content }}</main>
<footer class="container pb-4 text-center small"><a class="hash-link" href="{{ source_code_url }}" target="_blank" rel="noopener noreferrer">Source code</a> · AGPL-3.0-or-later</footer>
</body>
</html>"""

HOME_CONTENT = r"""<div class="hero-panel p-4 p-lg-5 mb-4"><h1 class="display-6 fw-bold">Cryptographic video identity without accounts</h1><p class="lead mb-3">An Ed25519 public key is the identity. The matching private key signs the literal list of every selected video's SHA-256 hash before the complete batch is uploaded.</p><div class="d-flex flex-wrap gap-2"><a class="btn btn-theme" href="/identity">Generate identity</a><a class="btn btn-outline-theme" href="/publish">Publish complete collection</a><a class="btn btn-outline-theme" href="/search">Search and verify</a></div></div>
<div class="row g-4"><div class="col-md-4"><div class="card h-100"><div class="card-body"><div class="feature-icon mb-3">1</div><h2 class="h5">Private-key control</h2><p class="small-muted mb-0">The private seed stays in page memory. The server receives only the public key, the detached signature, the signed hash list, and matching video bytes.</p></div></div></div><div class="col-md-4"><div class="card h-100"><div class="card-body"><div class="feature-icon mb-3">2</div><h2 class="h5">Direct hash-list signature</h2><p class="small-muted mb-0">The signature covers each SHA-256 hash as an explicit line. No combined collection hash replaces the individual video hashes.</p></div></div></div><div class="col-md-4"><div class="card h-100"><div class="card-body"><div class="feature-icon mb-3">3</div><h2 class="h5">Hash-addressed download</h2><p class="small-muted mb-0">Videos are stored and downloaded only by SHA-256. The browser recalculates the downloaded bytes before saving them.</p></div></div></div></div>"""

IDENTITY_CONTENT = r"""<div class="page-heading mb-4"><h1 class="h2 fw-bold">Create an Ed25519 identity</h1><p class="text-secondary">There is no account or registration database. Generate a private seed locally, save it, and share only the derived public key.</p></div>
<div class="row g-4"><div class="col-lg-4"><div class="card"><div class="card-header">New identity</div><div class="card-body"><div class="section-note rounded-3 p-3 mb-3"><strong>Private key = identity.</strong><div class="small-muted mt-1">Anyone who obtains the private seed can publish a signed hash list as this public key.</div></div><button id="generateIdentityButton" class="btn btn-theme w-100">Generate new Ed25519 identity</button><div id="identityStatus" class="status small mt-2"></div></div></div></div><div class="col-lg-8"><div class="card"><div class="card-header">Generated keys</div><div class="card-body"><div id="generatedIdentitySummary" class="identity-empty small-muted">No identity has been generated.</div><div id="generatedIdentityActions" class="d-none mt-3"><label class="form-label">Private key</label><textarea id="privateKeyOutput" class="form-control monospace" rows="2" readonly></textarea><label class="form-label mt-3">Public key</label><textarea id="publicKeyOutput" class="form-control monospace" rows="2" readonly></textarea><div class="d-flex flex-wrap gap-2 mt-3"><button id="downloadPrivateKeyButton" class="btn btn-outline-danger">Download private key</button><button id="copyPrivateKeyButton" class="btn btn-outline-danger">Copy private key</button><button id="copyPublicKeyButton" class="btn btn-outline-theme">Copy public key</button><a class="btn btn-theme" href="/publish">Publish videos</a></div></div></div></div></div></div>"""

PUBLISH_CONTENT = r"""<div class="page-heading mb-4"><h1 class="h2 fw-bold">Publish one complete signed video collection</h1><p class="text-secondary">Enter or import the private key. The public key is derived automatically. Select every video for this identity; the browser calculates each SHA-256 value and signs the complete list before upload.</p></div>
<div class="row g-4"><div class="col-lg-4"><div class="sticky-panel d-grid gap-4"><div class="card"><div class="card-header">Private key</div><div class="card-body"><textarea id="privateKeyInput" class="form-control monospace" rows="7" placeholder="Paste ed25519-private:... or a private-key JSON file"></textarea><input id="privateKeyFileInput" type="file" accept="application/json,.json" hidden><button id="importPrivateKeyButton" class="btn btn-outline-theme w-100 mt-3">Import private-key file</button><div id="privateKeyStatus" class="status small mt-2">Enter or import a private key. It is never uploaded.</div></div></div><div class="card"><div class="card-header">Derived public key</div><div class="card-body"><textarea id="derivedPublicKey" class="form-control monospace" rows="4" readonly placeholder="Derived automatically"></textarea></div></div></div></div><div class="col-lg-8"><div class="d-grid gap-4"><div class="card"><div class="card-header">Complete video set</div><div class="card-body"><div class="drop-zone"><input id="videoFiles" type="file" accept="video/*" multiple class="form-control" disabled><div class="small-muted mt-2">Select all videos at once. Filenames are ignored; only SHA-256 values and bytes matter. Changing the selection automatically recalculates and re-signs the list.</div></div><div class="progress mt-3"><div id="publicationProgressBar" class="progress-bar" style="width:0%"></div></div><div id="publicationStatus" class="status small mt-2"></div></div></div><div class="card"><div class="card-header">Signed individual hash list</div><div class="card-body"><div id="collectionPreview" class="d-grid gap-2"><div class="small-muted">No signed hash list prepared.</div></div><label class="form-label mt-3">Ed25519 signature</label><textarea id="signatureOutput" class="form-control monospace" rows="3" readonly></textarea><button id="publishCollectionButton" class="btn btn-theme w-100 mt-3" disabled>Upload all videos and publish atomically</button></div></div></div></div></div>"""

SEARCH_CONTENT = r"""<div class="page-heading mb-4"><h1 class="h2 fw-bold">Search by public key or video hash</h1><p class="text-secondary">A public-key search returns its complete signed SHA-256 list. A video-hash search returns the exact stored object and every public key whose valid signed list contains that hash.</p></div>
<div class="card mb-4"><div class="card-header">Cryptographic search</div><div class="card-body"><textarea id="searchInput" class="form-control monospace" rows="4" placeholder="Enter ed25519:... or a 64-character SHA-256 video hash"></textarea><button id="searchButton" class="btn btn-theme w-100 mt-3">Verify and search</button><div id="searchStatus" class="status small mt-2"></div></div></div><div id="searchResults" class="d-grid gap-3"></div>"""


def utc_timestamp():
    """Return a stable UTC timestamp for database records."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def configure_database_connection(database_connection):
    """Configure SQLite for concurrent Flask request threads."""
    database_connection.row_factory = sqlite3.Row
    database_connection.execute("PRAGMA foreign_keys=ON")
    database_connection.execute("PRAGMA journal_mode=WAL")
    database_connection.execute("PRAGMA busy_timeout=30000")
    return database_connection


def get_database_connection():
    """Return one request-scoped SQLite connection."""
    if "database_connection" not in g:
        database_connection = sqlite3.connect(DATABASE_PATH, timeout=30)
        g.database_connection = configure_database_connection(database_connection)
    return g.database_connection


@application.teardown_appcontext
def close_database_connection(_exception=None):
    """Close the request-scoped SQLite connection."""
    database_connection = g.pop("database_connection", None)
    if database_connection is not None:
        database_connection.close()


def initialize_database():
    """Create public-key collections and SHA-256 object tables."""
    database_connection = configure_database_connection(sqlite3.connect(DATABASE_PATH, timeout=30))
    database_connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS objects(
            hash TEXT PRIMARY KEY,
            size INTEGER NOT NULL,
            path TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS collections(
            public_key TEXT PRIMARY KEY,
            hashes_json TEXT NOT NULL,
            signature TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS collection_objects(
            public_key TEXT NOT NULL,
            object_hash TEXT NOT NULL,
            position INTEGER NOT NULL,
            PRIMARY KEY(public_key,object_hash),
            UNIQUE(public_key,position),
            FOREIGN KEY(public_key) REFERENCES collections(public_key) ON DELETE CASCADE,
            FOREIGN KEY(object_hash) REFERENCES objects(hash) ON DELETE RESTRICT
        );
        CREATE INDEX IF NOT EXISTS collection_objects_hash_index ON collection_objects(object_hash);
        """
    )
    database_connection.close()


def json_error(message, status_code=400):
    """Return a consistent JSON error response."""
    return jsonify(error=message), status_code


def base64url_encode(binary_value):
    """Encode bytes as unpadded Base64URL text."""
    return base64.urlsafe_b64encode(binary_value).decode("ascii").rstrip("=")


def base64url_decode(encoded_value):
    """Decode a bounded unpadded Base64URL value."""
    if not isinstance(encoded_value, str) or len(encoded_value) > 1000:
        raise ValueError("Invalid Base64URL value")
    padding_text = "=" * ((-len(encoded_value)) % 4)
    return base64.urlsafe_b64decode(encoded_value + padding_text)


def normalize_public_key(public_key_text):
    """Parse one raw Ed25519 public key as the complete identity."""
    if not isinstance(public_key_text, str):
        raise ValueError("Invalid Ed25519 public key")
    public_key_match = PUBLIC_KEY_PATTERN.fullmatch(public_key_text.strip())
    if public_key_match is None:
        raise ValueError("Public key must use ed25519:<base64url> format")
    try:
        public_key_bytes = base64url_decode(public_key_match.group(1))
    except (ValueError, binascii.Error) as decoding_error:
        raise ValueError("Invalid Ed25519 public key encoding") from decoding_error
    if len(public_key_bytes) != 32:
        raise ValueError("Ed25519 public key must contain exactly 32 bytes")
    normalized_public_key = "ed25519:" + base64url_encode(public_key_bytes)
    verification_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    return verification_key, normalized_public_key


def decode_signature(signature_text):
    """Decode one detached 64-byte Ed25519 signature."""
    try:
        signature_bytes = base64url_decode(signature_text)
    except (ValueError, binascii.Error) as decoding_error:
        raise ValueError("Invalid Ed25519 signature encoding") from decoding_error
    if len(signature_bytes) != 64:
        raise ValueError("Ed25519 signature must contain exactly 64 bytes")
    return signature_bytes


def normalize_hash_list(hash_values):
    """Validate the exact sorted list of individual SHA-256 values."""
    if not isinstance(hash_values, list) or not hash_values:
        raise ValueError("At least one video hash is required")
    if len(hash_values) > MAX_COLLECTION_FILES:
        raise ValueError("The collection contains too many videos")
    normalized_hashes = [str(hash_value).lower() for hash_value in hash_values]
    if any(HASH_PATTERN.fullmatch(hash_value) is None for hash_value in normalized_hashes):
        raise ValueError("The list contains an invalid SHA-256 hash")
    if normalized_hashes != sorted(set(normalized_hashes)):
        raise ValueError("Hashes must be unique and sorted")
    return normalized_hashes


def build_signature_message(public_key, hash_values):
    """Build the message that directly lists every signed SHA-256 value."""
    _verification_key, normalized_public_key = normalize_public_key(public_key)
    normalized_hashes = normalize_hash_list(hash_values)
    hash_lines = "\n".join(f"HASH {hash_value}" for hash_value in normalized_hashes)
    return f"{COLLECTION_SIGNATURE_PREFIX}\nPUBLIC-KEY {normalized_public_key}\n{hash_lines}"


def verify_hash_list_signature(verification_key, public_key, hash_values, signature_text):
    """Verify the direct newline-delimited hash-list signature."""
    try:
        verification_key.verify(decode_signature(signature_text), build_signature_message(public_key, hash_values).encode("utf-8"))
        return True
    except (InvalidSignature, ValueError, binascii.Error):
        return False


def calculate_file_hash(file_path):
    """Stream one file through SHA-256 without loading it fully into memory."""
    hash_calculator = hashlib.sha256()
    with open(file_path, "rb") as input_file:
        for file_chunk in iter(lambda: input_file.read(4 * 1024 * 1024), b""):
            hash_calculator.update(file_chunk)
    return hash_calculator.hexdigest()


def stage_uploaded_file(uploaded_file, staging_directory, file_index):
    """Stage and hash one uploaded video while ignoring its filename."""
    temporary_path = staging_directory / f"object-{file_index:08d}.part"
    hash_calculator = hashlib.sha256()
    total_size = 0
    with open(temporary_path, "wb") as output_file:
        while True:
            file_chunk = uploaded_file.stream.read(4 * 1024 * 1024)
            if not file_chunk:
                break
            output_file.write(file_chunk)
            hash_calculator.update(file_chunk)
            total_size += len(file_chunk)
    return {"hash": hash_calculator.hexdigest(), "size": total_size, "temporary_path": temporary_path}


def place_verified_object(temporary_path, object_hash):
    """Atomically place verified bytes at their SHA-256 address."""
    object_path = OBJECT_DIRECTORY / object_hash
    with OBJECT_STORAGE_LOCK:
        if object_path.exists() and calculate_file_hash(object_path) == object_hash:
            temporary_path.unlink(missing_ok=True)
            return object_path
        os.replace(temporary_path, object_path)
    return object_path


def validate_existing_collection(database_connection, public_key, hash_values, signature_text):
    """Reject any attempt to replace one public key's immutable signed list."""
    collection_row = database_connection.execute(
        "SELECT hashes_json,signature FROM collections WHERE public_key=?",
        (public_key,),
    ).fetchone()
    if collection_row is None:
        return
    stored_hashes = json.loads(collection_row["hashes_json"])
    if stored_hashes != hash_values or collection_row["signature"] != signature_text:
        raise sqlite3.IntegrityError("This public key already has a different immutable signed hash list")


def store_atomic_collection(public_key, hash_values, signature_text, staged_objects):
    """Expose the collection only after every signature and file check succeeds."""
    database_connection = get_database_connection()
    validate_existing_collection(database_connection, public_key, hash_values, signature_text)
    stored_objects = []
    for staged_object in staged_objects:
        object_path = place_verified_object(staged_object["temporary_path"], staged_object["hash"])
        stored_objects.append({**staged_object, "path": object_path})
    current_timestamp = utc_timestamp()
    database_connection.execute("BEGIN IMMEDIATE")
    validate_existing_collection(database_connection, public_key, hash_values, signature_text)
    for stored_object in stored_objects:
        database_connection.execute(
            "INSERT INTO objects(hash,size,path,created_at) VALUES(?,?,?,?) "
            "ON CONFLICT(hash) DO UPDATE SET size=excluded.size,path=excluded.path",
            (stored_object["hash"], stored_object["size"], str(stored_object["path"]), current_timestamp),
        )
    database_connection.execute(
        "INSERT OR IGNORE INTO collections(public_key,hashes_json,signature,created_at) VALUES(?,?,?,?)",
        (public_key, json.dumps(hash_values, separators=(",", ":")), signature_text, current_timestamp),
    )
    for object_position, object_hash in enumerate(hash_values):
        database_connection.execute(
            "INSERT OR IGNORE INTO collection_objects(public_key,object_hash,position) VALUES(?,?,?)",
            (public_key, object_hash, object_position),
        )
    database_connection.commit()
    return current_timestamp


def check_object_integrity(object_hash, object_path_text):
    """Return availability and optional SHA-256 integrity for one object."""
    if not object_path_text:
        return object_hash, False, None
    object_path = Path(object_path_text)
    if not object_path.is_file():
        return object_hash, False, None
    if not VERIFY_OBJECTS_ON_SEARCH:
        return object_hash, True, None
    return object_hash, True, calculate_file_hash(object_path) == object_hash


def calculate_integrity_results(object_rows):
    """Rehash independent objects concurrently during public-key search."""
    integrity_arguments = [(object_row["object_hash"], object_row["path"]) for object_row in object_rows]
    if not integrity_arguments:
        return {}
    worker_count = min(INTEGRITY_WORKER_COUNT, len(integrity_arguments))
    with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="object-integrity") as executor:
        integrity_results = executor.map(lambda values: check_object_integrity(*values), integrity_arguments)
    return {object_hash: (object_available, object_integrity) for object_hash, object_available, object_integrity in integrity_results}


def build_development_ssl_context():
    """Return Werkzeug ad-hoc TLS unless HTTP is explicitly selected."""
    if DEVELOPMENT_TLS_MODE in {"0", "false", "off", "none", "http"}:
        return None
    return "adhoc"


def render_platform_page(page_title, active_page, page_content, page_javascript=""):
    """Render one module from frontend source embedded in this server.py file."""
    csp_nonce = secrets.token_urlsafe(18)
    g.csp_nonce = csp_nonce
    return render_template_string(
        PAGE_TEMPLATE,
        page_title=page_title,
        active_page=active_page,
        page_content=Markup(page_content),
        page_javascript=Markup(page_javascript),
        crypto_javascript=Markup(CRYPTO_JAVASCRIPT),
        common_javascript=Markup(COMMON_JAVASCRIPT),
        theme_css=Markup(THEME_CSS),
        source_code_url=SOURCE_CODE_URL,
        csp_nonce=csp_nonce,
    )


@application.after_request
def apply_security_headers(response):
    """Apply security headers while permitting the Bootstrap stylesheet."""
    csp_nonce = getattr(g, "csp_nonce", None)
    script_policy = f"script-src 'nonce-{csp_nonce}'" if csp_nonce else "script-src 'none'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        f"default-src 'self'; {script_policy}; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    )
    return response


@application.get("/")
def index_page():
    return render_platform_page("Home", "home", HOME_CONTENT)


@application.get("/identity")
def identity_page():
    return render_platform_page("Identity", "identity", IDENTITY_CONTENT, IDENTITY_JAVASCRIPT)


@application.get("/publish")
def publish_page():
    return render_platform_page("Publish", "publish", PUBLISH_CONTENT, PUBLISH_JAVASCRIPT)


@application.get("/search")
def search_page():
    return render_platform_page("Search", "search", SEARCH_CONTENT, SEARCH_JAVASCRIPT)


@application.get("/api/health")
def health_check():
    return jsonify(status="ok", protocol=COLLECTION_PROTOCOL, signature_algorithm="Ed25519", content_hash="SHA-256", identity="public-key", threaded=True)


@application.post("/api/collections")
def publish_collection():
    uploaded_files = request.files.getlist("videos")
    public_key_text = str(request.form.get("public_key", "")).strip()
    signature_text = str(request.form.get("signature", "")).strip()
    hash_list_text = str(request.form.get("hashes", "")).strip()
    if not uploaded_files:
        return json_error("The complete video collection is required")
    try:
        hash_values = normalize_hash_list(json.loads(hash_list_text))
        verification_key, normalized_public_key = normalize_public_key(public_key_text)
    except (ValueError, json.JSONDecodeError) as validation_error:
        return json_error(str(validation_error))
    if not verify_hash_list_signature(verification_key, normalized_public_key, hash_values, signature_text):
        return json_error("Ed25519 hash-list signature verification failed", 403)
    if len(uploaded_files) != len(hash_values):
        return json_error("Every signed hash must have exactly one uploaded video in the same request", 409)
    staging_directory = Path(tempfile.mkdtemp(prefix="collection-", dir=TEMPORARY_DIRECTORY))
    try:
        staged_objects = []
        for file_index, uploaded_file in enumerate(uploaded_files):
            staged_object = stage_uploaded_file(uploaded_file, staging_directory, file_index)
            expected_hash = hash_values[file_index]
            if staged_object["hash"] != expected_hash:
                return json_error(f"Uploaded object {file_index + 1} does not match signed hash {expected_hash}", 409)
            staged_objects.append(staged_object)
        try:
            created_at = store_atomic_collection(normalized_public_key, hash_values, signature_text, staged_objects)
        except sqlite3.IntegrityError as integrity_error:
            get_database_connection().rollback()
            return json_error(str(integrity_error), 409)
        return jsonify(ok=True, public_key=normalized_public_key, object_count=len(hash_values), hashes=hash_values, signature_valid=True, created_at=created_at)
    except Exception:
        get_database_connection().rollback()
        raise
    finally:
        shutil.rmtree(staging_directory, ignore_errors=True)


def load_signed_object_rows(hash_values):
    """Load object records by the signed hashes instead of trusting relationship rows."""
    database_connection = get_database_connection()
    object_rows_by_hash = {}
    chunk_size = 500
    for chunk_start in range(0, len(hash_values), chunk_size):
        hash_chunk = hash_values[chunk_start:chunk_start + chunk_size]
        placeholders = ",".join("?" for _hash_value in hash_chunk)
        object_rows = database_connection.execute(
            f"SELECT hash AS object_hash,size,path FROM objects WHERE hash IN ({placeholders})",
            tuple(hash_chunk),
        ).fetchall()
        object_rows_by_hash.update({object_row["object_hash"]: object_row for object_row in object_rows})
    return object_rows_by_hash


def search_by_public_key(public_key_text):
    """Return one public key's list only after verifying its stored signature."""
    verification_key, normalized_public_key = normalize_public_key(public_key_text)
    database_connection = get_database_connection()
    collection_row = database_connection.execute(
        "SELECT hashes_json,signature,created_at FROM collections WHERE public_key=?",
        (normalized_public_key,),
    ).fetchone()
    if collection_row is None:
        return None
    hash_values = normalize_hash_list(json.loads(collection_row["hashes_json"]))
    signature_valid = verify_hash_list_signature(verification_key, normalized_public_key, hash_values, collection_row["signature"])
    if not signature_valid:
        raise RuntimeError("Stored Ed25519 signature verification failed")
    object_rows_by_hash = load_signed_object_rows(hash_values)
    integrity_rows = []
    for object_hash in hash_values:
        object_row = object_rows_by_hash.get(object_hash)
        integrity_rows.append({"object_hash": object_hash, "path": object_row["path"] if object_row else None})
    integrity_by_hash = calculate_integrity_results(integrity_rows)
    objects = []
    for object_hash in hash_values:
        object_row = object_rows_by_hash.get(object_hash)
        object_available, object_integrity = integrity_by_hash.get(object_hash, (False, None))
        objects.append({"hash": object_hash, "size": object_row["size"] if object_row else None, "object_available": object_available, "object_integrity": object_integrity})
    return {"type": "public_key", "public_key": normalized_public_key, "hashes": hash_values, "signature": collection_row["signature"], "signature_valid": True, "created_at": collection_row["created_at"], "objects": objects}


def search_by_hash(object_hash):
    """Return the object and only cryptographically verified public-key references."""
    database_connection = get_database_connection()
    object_row = database_connection.execute("SELECT size,path FROM objects WHERE hash=?", (object_hash,)).fetchone()
    candidate_rows = database_connection.execute(
        "SELECT c.public_key,c.hashes_json,c.signature FROM collection_objects co "
        "JOIN collections c ON c.public_key=co.public_key WHERE co.object_hash=? ORDER BY c.public_key ASC",
        (object_hash,),
    ).fetchall()
    verified_public_keys = []
    for candidate_row in candidate_rows:
        try:
            verification_key, normalized_public_key = normalize_public_key(candidate_row["public_key"])
            hash_values = normalize_hash_list(json.loads(candidate_row["hashes_json"]))
        except (ValueError, json.JSONDecodeError):
            continue
        signature_valid = verify_hash_list_signature(verification_key, normalized_public_key, hash_values, candidate_row["signature"])
        if signature_valid and object_hash in hash_values:
            verified_public_keys.append(normalized_public_key)
    if object_row is None and not verified_public_keys:
        return None
    object_available = False
    object_integrity = None
    object_size = None
    if object_row is not None:
        object_size = object_row["size"]
        _hash_value, object_available, object_integrity = check_object_integrity(object_hash, object_row["path"])
    return {"type": "hash", "hash": object_hash, "size": object_size, "object_available": object_available, "object_integrity": object_integrity, "public_keys": verified_public_keys}


@application.post("/api/search")
def cryptographic_search():
    request_data = request.get_json(silent=True) or {}
    search_query = str(request_data.get("query", "")).strip()
    try:
        if HASH_PATTERN.fullmatch(search_query.lower()) is not None:
            search_result = search_by_hash(search_query.lower())
        else:
            search_result = search_by_public_key(search_query)
    except ValueError as validation_error:
        return json_error(str(validation_error))
    except RuntimeError as verification_error:
        return json_error(str(verification_error), 409)
    if search_result is None:
        return json_error("No matching signed collection or video object was found", 404)
    return jsonify(search_result)


@application.get("/object/<object_hash>")
def download_object(object_hash):
    normalized_object_hash = object_hash.lower()
    if HASH_PATTERN.fullmatch(normalized_object_hash) is None:
        return json_error("Invalid SHA-256 hash")
    object_row = get_database_connection().execute("SELECT size,path FROM objects WHERE hash=?", (normalized_object_hash,)).fetchone()
    if object_row is None:
        return json_error("No stored object matches this hash", 404)
    object_path = Path(object_row["path"])
    if not object_path.is_file():
        return json_error("The signed hash exists, but the video object is unavailable", 410)
    if calculate_file_hash(object_path) != normalized_object_hash:
        return json_error("Stored object integrity verification failed", 409)
    response = send_file(object_path, mimetype="application/octet-stream", as_attachment=True, download_name=f"{normalized_object_hash}.video", conditional=True, etag=normalized_object_hash)
    response.headers["X-Content-SHA256"] = normalized_object_hash
    response.headers["Cache-Control"] = "public, immutable, max-age=31536000"
    return response

initialize_database()

if __name__ == "__main__":
    application.run(host="0.0.0.0", port=443, debug=False, threaded=True, ssl_context=build_development_ssl_context())




