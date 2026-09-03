document.addEventListener('DOMContentLoaded', () => {
  const themes = {baltic:'Baltic',night:'Night',parchment:'Parchment',terminal:'Terminal',blu:'Blue',noir:'Noir',fox:'Fox',aurora:'Aurora',midnight:'Midnight',white:'White',black:'Black'};
  const themeKeys = Object.keys(themes);
  requestAnimationFrame(() => document.body.classList.add('site-ready'));

  const progress = document.body.appendChild(document.createElement('div'));
  progress.className = 'reading-progress';
  progress.setAttribute('aria-hidden', 'true');
  const updateProgress = () => {
    const length = document.documentElement.scrollHeight - innerHeight;
    progress.style.transform = `scaleX(${length > 0 ? scrollY / length : 0})`;
  };
  updateProgress();
  addEventListener('scroll', updateProgress, {passive:true});
  addEventListener('resize', updateProgress);

  const toast = document.body.appendChild(document.createElement('div'));
  toast.className = 'theme-toast';
  toast.setAttribute('role', 'status');
  let toastTimer;
  const themeButton = document.querySelector('.theme-toggle');
  const announceTheme = key => {
    toast.textContent = themes[key];
    toast.classList.add('visible');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove('visible'), 900);
  };
  const setTheme = key => {
    document.body.classList.remove(...themeKeys);
    document.body.classList.add(key);
    localStorage.setItem('themeIndex', themeKeys.indexOf(key));
    announceTheme(key);
  };

  const themeDialog = document.body.appendChild(document.createElement('dialog'));
  themeDialog.className = 'theme-picker';
  themeDialog.innerHTML = `<div class="theme-picker-box"><h2>Choose a theme</h2><div class="theme-options">${themeKeys.map(key => `<button type="button" data-theme="${key}"><span class="theme-swatch ${key}"></span>${themes[key]}</button>`).join('')}</div><button class="theme-close" type="button">Close</button></div>`;
  themeDialog.querySelector('.theme-close').addEventListener('click', () => themeDialog.close());
  themeDialog.addEventListener('click', event => { if (event.target === themeDialog) themeDialog.close(); });
  const updateThemeSelection = () => {
    themeDialog.querySelectorAll('[data-theme]').forEach(button => {
      button.setAttribute('aria-pressed', document.body.classList.contains(button.dataset.theme));
    });
  };
  themeDialog.querySelectorAll('[data-theme]').forEach(button => button.addEventListener('click', () => {
    setTheme(button.dataset.theme);
    updateThemeSelection();
    themeDialog.close();
  }));

  themeButton?.addEventListener('click', event => {
    event.stopImmediatePropagation();
    themeButton.classList.remove('spin');
    void themeButton.offsetWidth;
    themeButton.classList.add('spin');
    updateThemeSelection();
    themeDialog.showModal();
  }, true);

  if (!matchMedia('(prefers-reduced-motion: reduce)').matches) {
    document.querySelectorAll('.book').forEach(book => {
      const cover = book.querySelector('img');
      book.addEventListener('pointermove', event => {
        const box = book.getBoundingClientRect();
        const x = (event.clientX - box.left) / box.width - .5;
        const y = (event.clientY - box.top) / box.height - .5;
        cover.style.transform = `perspective(600px) rotateX(${-y*5}deg) rotateY(${x*6}deg) translateY(-2px)`;
      });
      book.addEventListener('pointerleave', () => { cover.style.transform = ''; });
    });
  }

  const incipitSearch = document.querySelector('#incipit-search');
  incipitSearch?.addEventListener('input', () => {
    const query = incipitSearch.value.trim().toLocaleLowerCase();
    document.querySelectorAll('.incipit-index li').forEach(item => {
      item.hidden = !item.textContent.toLocaleLowerCase().includes(query);
    });
  });

  const backToIndex = document.querySelector('.back-to-index');
  const incipitIndex = document.querySelector('#incipit-index');
  if (backToIndex && incipitIndex) {
    new IntersectionObserver(([entry]) => {
      backToIndex.classList.toggle('visible', !entry.isIntersecting);
    }).observe(incipitIndex);
  }

  const dialog = document.body.appendChild(document.createElement('dialog'));
  dialog.className = 'command-palette';
  dialog.innerHTML = '<form method="dialog" class="command-box"><label for="command-search">Jump anywhere</label><input id="command-search" type="search" autocomplete="off" placeholder="Search pages and books…"><div class="command-results"></div><small><kbd>↑</kbd><kbd>↓</kbd> move · <kbd>Enter</kbd> open · <kbd>Esc</kbd> close</small></form>';
  const commands = [['Home','index.html'],['Research','papers.html'],['Talks','talks.html'],['Events','conferences.html'],['Favorites','favorites.html'],['Incipits','incipits.html'],['Plaintext editor','plaintext/'],['BLAKE3 visualizer','b3viz/'],["Murphy’s laws",'murphy.html']];
  document.querySelectorAll('#incipits h3[id]').forEach(h => commands.push([h.textContent.trim(),`incipits.html#${h.id}`]));
  const input = dialog.querySelector('input');
  const results = dialog.querySelector('.command-results');
  let selected=0, visible=[];
  const render = () => {
    const query=input.value.trim().toLocaleLowerCase();
    visible=commands.filter(([name]) => name.toLocaleLowerCase().includes(query)).slice(0,8);
    selected=Math.min(selected,Math.max(visible.length-1,0));
    results.innerHTML=visible.map(([name,url],i)=>`<a href="${url}"${i===selected?' class="selected"':''}>${name}</a>`).join('')||'<p>No matches</p>';
  };
  const open = () => { selected=0; input.value=''; render(); dialog.showModal(); input.focus(); };
  input.addEventListener('input',render);
  input.addEventListener('keydown',event => {
    if ((event.key==='ArrowDown'||event.key==='ArrowUp') && visible.length) { event.preventDefault(); selected=(selected+(event.key==='ArrowDown'?1:-1)+visible.length)%visible.length; render(); }
    if (event.key==='Enter'&&visible[selected]) { event.preventDefault(); location.href=visible[selected][1]; }
  });
  dialog.addEventListener('click',event => { if(event.target===dialog) dialog.close(); });
  document.addEventListener('keydown',event => {
    const typing=/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName);
    if ((event.key==='/'&&!typing)||((event.metaKey||event.ctrlKey)&&event.key.toLowerCase()==='k')) { event.preventDefault(); dialog.open?dialog.close():open(); }
    else if(event.key.toLowerCase()==='t'&&!typing&&!dialog.open&&!themeDialog.open&&themeButton) {
      const current = themeKeys.findIndex(key => document.body.classList.contains(key));
      setTheme(themeKeys[(current + 1) % themeKeys.length]);
    }
  });

  const footer = document.createElement('footer');
  footer.className = 'site-footer';
  footer.innerHTML = '<div><a href="https://www.bfswa.blog">Blog</a><a href="https://github.com/veorq">GitHub</a><a href="mailto:jpa@pm.me">Email</a><span>Signal: jpa.01</span></div><small><kbd>/</kbd> search · <kbd>T</kbd> theme</small>';
  document.querySelector('#content')?.append(footer);
});
