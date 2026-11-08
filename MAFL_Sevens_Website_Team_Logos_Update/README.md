# MAFL Sevens — public website (first working version)

This is a **static, responsive public website** built from the uploaded `MAFL_Sevens_Master_Data_Workbook(2).xlsx`. It uses the original uploaded MAFL crest in `assets/mafl-logo.png`. No hosting, account access, database or administrator dashboard has been set up yet.

## Pages
- Home: latest results, next scheduled fixtures, competition overview
- Fixtures & Results: filter by competition, match state and confirmation status
- League Tables: Division 1 and Division 2, calculated only from played fixtures in the relevant competition
- Player Stats: goals, appearances, MOTM, GKOTM, yellow and red cards
- Teams: division filter, team list and player squads

## How to preview locally
1. Extract the ZIP.
2. Open a terminal in the `mafl-sevens-public` folder.
3. Run `python -m http.server 8000`.
4. Visit `http://localhost:8000` in your browser.

Double-clicking `index.html` may not work because browsers restrict local JSON requests.

## Publish on Cloudflare Pages
1. Create a GitHub repository and upload **the contents** of this folder, preserving `index.html` at the repository root.
2. In Cloudflare, create a Pages project linked to that repository.
3. Choose a static/no-framework setup, with no build command and the repository root as output directory (`.`), if supported by the interface.
4. Deploy and open the provided Pages URL. The website will be publicly accessible.

Cloudflare's interface and free-plan allowances may change. Review the current deployment instructions and free-tier limits before publishing.

## Data and accuracy notes
- Source: user's latest uploaded Master Data Workbook, extracted once into `data/league.json`.
- The site **does not yet update itself from Excel**. Updating `data/league.json` requires a new export/redeployment until the importer is built.
- `Match Performance` currently has **no Assists column**, so assists and goal contributions are intentionally omitted.
- Player appearances count rows marked `Played=Yes`.
- Standings use 3 points for a win and sort by points, goal difference, goals for. Verify the league's official tie-break regulations before relying on them for final placements.
- Fixtures without team IDs are shown as “To be confirmed”.
- Image filename columns contain `#VALUE!` in the uploaded workbook. These were ignored. Team images are placeholders until the admin image upload feature exists.
- The uploaded News sheet has no news entries, so the initial public website does not show a news feed.
- The website includes data from the uploaded workbook, including personal names. Review before publishing publicly.
- No private/admin area, authentication, image uploads, Excel imports, D1 database or PWA install features are implemented in this version.

## Next phase
Build the Excel importer with validation, preview, and stable-ID upsert; add Cloudflare D1 storage and private admin login; support uploaded logos and player photos; verify discipline rules and assist tracking.
