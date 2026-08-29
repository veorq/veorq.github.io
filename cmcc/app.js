(() => {
  const data = window.CONCORDANCE_DATA;
  const bookById = Object.fromEntries(data.books.map(book => [book.id, book]));
  const prominenceRank = { principal: 0, major: 1, secondary: 2, minor: 3 };

  const elements = {
    search: document.querySelector('#search'),
    book: document.querySelector('#book-filter'),
    kind: document.querySelector('#kind-filter'),
    role: document.querySelector('#role-filter'),
    clear: document.querySelector('#clear-filters'),
    count: document.querySelector('#result-count'),
    results: document.querySelector('#results'),
    detail: document.querySelector('#detail'),
    bookGrid: document.querySelector('#book-grid'),
    sourceNote: document.querySelector('#source-note'),
    updated: document.querySelector('#updated'),
    coverageJump: document.querySelector('#coverage-jump')
  };

  const state = {
    query: '',
    book: 'all',
    kind: 'all',
    role: 'all',
    selected: location.hash.slice(1) || null
  };

  const normalize = value => String(value || '')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase();

  const searchableText = character => normalize([
    character.name,
    ...character.aliases,
    character.kind,
    character.prominence,
    character.description,
    ...character.dates,
    ...character.locations,
    ...character.books.map(id => bookById[id]?.title || ''),
    ...character.references.flatMap(ref => [ref.locator, ref.note])
  ].join(' '));

  data.characters.forEach(character => {
    character._search = searchableText(character);
  });

  function filteredCharacters() {
    const terms = normalize(state.query).split(/\s+/).filter(Boolean);
    return data.characters
      .filter(character => state.book === 'all' || character.books.includes(state.book))
      .filter(character => state.kind === 'all' || character.kind === state.kind)
      .filter(character => state.role === 'all' || character.prominence === state.role)
      .filter(character => terms.every(term => character._search.includes(term)))
      .sort((a, b) =>
        prominenceRank[a.prominence] - prominenceRank[b.prominence] ||
        a.name.localeCompare(b.name)
      );
  }

  function bookTitles(character) {
    return character.books.map(id => bookById[id].title).join(' · ');
  }

  function escapeHtml(value) {
    return String(value)
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#039;');
  }

  function renderResults() {
    const characters = filteredCharacters();
    elements.count.textContent = `${characters.length} ${characters.length === 1 ? 'character' : 'characters'} found`;

    if (!characters.length) {
      elements.results.innerHTML = `
        <div class="empty-state">
          <strong>No one came out of the dark.</strong>
          Try another name, place, date, or filter.
        </div>`;
      elements.detail.innerHTML = '';
      return;
    }

    if (!characters.some(character => character.id === state.selected)) {
      state.selected = characters[0].id;
    }

    elements.results.innerHTML = characters.map((character, index) => `
      <button class="result-card" type="button" role="option"
        data-id="${escapeHtml(character.id)}"
        aria-selected="${character.id === state.selected}">
        <span class="result-number">${String(index + 1).padStart(2, '0')}</span>
        <span>
          <span class="result-name">${escapeHtml(character.name)}</span>
          <span class="result-meta">${escapeHtml(bookTitles(character))} · ${escapeHtml(character.kind)}</span>
        </span>
        <span class="result-arrow" aria-hidden="true">→</span>
      </button>`).join('');

    elements.results.querySelectorAll('[data-id]').forEach(button => {
      button.addEventListener('click', () => selectCharacter(button.dataset.id, true));
    });

    renderDetail();
  }

  function selectCharacter(id, userInitiated = false) {
    state.selected = id;
    history.replaceState(null, '', `#${id}`);
    elements.results.querySelectorAll('[data-id]').forEach(button => {
      button.setAttribute('aria-selected', String(button.dataset.id === id));
    });
    renderDetail();
    if (userInitiated && window.matchMedia('(max-width: 900px)').matches) {
      elements.detail.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }

  function renderDetail() {
    const character = data.characters.find(item => item.id === state.selected);
    if (!character) return;

    const aliases = character.aliases.length
      ? `<p class="aliases">Also: ${character.aliases.map(escapeHtml).join(', ')}</p>`
      : '';

    elements.detail.innerHTML = `
      <div class="detail-kicker">
        <span class="tag tag--red">${escapeHtml(character.prominence)}</span>
        <span class="tag">${escapeHtml(character.kind)}</span>
        ${character.books.map(id => `<span class="tag">${escapeHtml(bookById[id].title)}</span>`).join('')}
      </div>
      <h2>${escapeHtml(character.name)}</h2>
      ${aliases}
      <p class="description">${escapeHtml(character.description)}</p>
      <div class="detail-grid">
        <section class="detail-section">
          <h3>Dates</h3>
          <ul class="plain-list">${character.dates.map(date => `<li>${escapeHtml(date)}</li>`).join('')}</ul>
        </section>
        <section class="detail-section">
          <h3>Places</h3>
          <ul class="plain-list">${character.locations.map(place => `<li>${escapeHtml(place)}</li>`).join('')}</ul>
        </section>
        <section class="detail-section reference-list">
          <h3>References</h3>
          <ul class="reference-list">
            ${character.references.map(reference => `
              <li>
                <strong><em>${escapeHtml(bookById[reference.book].title)}</em><br>${escapeHtml(reference.locator)}</strong>
                <span>${escapeHtml(reference.note)}</span>
              </li>`).join('')}
          </ul>
        </section>
      </div>`;
  }

  function renderCoverage() {
    elements.bookGrid.innerHTML = data.books.map(book => {
      const count = data.characters.filter(character => character.books.includes(book.id)).length;
      return `
        <article class="book-card ${book.indexed ? 'book-card--indexed' : ''}">
          <p class="book-status">${book.indexed ? `Indexed · ${count} entries` : 'Not indexed yet'}</p>
          <h3>${escapeHtml(book.title)}</h3>
          <span class="book-year">${book.year}</span>
        </article>`;
    }).join('');
  }

  function populateBookFilter() {
    data.books.filter(book => book.indexed).forEach(book => {
      const option = document.createElement('option');
      option.value = book.id;
      option.textContent = book.title;
      elements.book.appendChild(option);
    });
  }

  function clearFilters() {
    state.query = '';
    state.book = 'all';
    state.kind = 'all';
    state.role = 'all';
    elements.search.value = '';
    elements.book.value = 'all';
    elements.kind.value = 'all';
    elements.role.value = 'all';
    renderResults();
    elements.search.focus();
  }

  elements.search.addEventListener('input', event => {
    state.query = event.target.value;
    renderResults();
  });
  elements.book.addEventListener('change', event => {
    state.book = event.target.value;
    renderResults();
  });
  elements.kind.addEventListener('change', event => {
    state.kind = event.target.value;
    renderResults();
  });
  elements.role.addEventListener('change', event => {
    state.role = event.target.value;
    renderResults();
  });
  elements.clear.addEventListener('click', clearFilters);
  elements.coverageJump.addEventListener('click', () => {
    document.querySelector('#coverage').scrollIntoView({ behavior: 'smooth' });
  });

  document.addEventListener('keydown', event => {
    if (event.key === '/' && document.activeElement !== elements.search) {
      event.preventDefault();
      elements.search.focus();
    }
    if (event.key === 'Escape' && document.activeElement === elements.search) {
      clearFilters();
    }
  });

  window.addEventListener('hashchange', () => {
    const id = location.hash.slice(1);
    if (data.characters.some(character => character.id === id)) selectCharacter(id);
  });

  elements.sourceNote.textContent = data.meta.sourceNote;
  elements.updated.textContent = `Updated ${data.meta.updated}`;
  populateBookFilter();
  renderCoverage();
  renderResults();
})();
