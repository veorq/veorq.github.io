# Cormac McCarthy Character Index

A dependency-free static web application indexing all twelve Cormac McCarthy
novels, from *The Orchard Keeper* through *Stella Maris*.

## Install

Upload this entire directory to your web server without changing its internal
file structure. For example, if the directory is named `mccarthy`, the app will
be available at:

```text
https://www.aumasson.jp/mccarthy/
```

No build step, server-side code, database, or network request is required.

## Files

- `index.html` — page structure and metadata
- `styles.css` — responsive visual design
- `data.js` — books, characters, places, dates, and references
- `app.js` — client-side search, filtering, selection, and coverage display

## Extend the corpus

Add a book record to the `books` array in `data.js`, set `indexed: true`, and
add character records that refer to the book's `id`. Every character record is
searchable across its name, aliases, description, dates, locations, books, and
references.

The application intentionally contains no source text from the novels.
