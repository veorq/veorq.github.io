BLAKE3 Diffusion Lab — static deployment

Upload the CONTENTS of this directory to the directory mapped to:
https://www.aumasson.jp/b3viz/

Required files:
  index.html
  favicon.svg
  og.png
  assets/app.css
  assets/app.js

No Node.js process, package installation, build command, database, or server-side
code is required. The application is entirely client-side. The asset references
are relative, so the directory can also be tested from any ordinary static HTTP
server before deployment.

Important: do not open index.html directly as a file:// URL. Serve the directory
over HTTP(S), because its Content Security Policy only permits same-origin assets.
