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

The interface sounds are synthesized locally with the Web Audio API. There are
no audio files, trackers, third-party scripts, or network requests. Browsers only
permit audio after a user interaction; clicking a control activates it. The SFX
switch in the header disables all sound.

The light/dark theme switch is also entirely local. Dark is the default, and the
selected theme is remembered in the browser's local storage for later visits.

Important: do not open index.html directly as a file:// URL. Serve the directory
over HTTP(S), because its Content Security Policy only permits same-origin assets.
