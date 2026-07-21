# Exercise 1 — Draw a Data-Flow Diagram

**Goal:** Draw the Level 1 DFD for Juice Shop's login, browse, basket/checkout, and admin flows yourself — not by copying Lecture 1's diagram, but by observing your own running lab instance and drawing what you actually see.

**Estimated time:** 90 minutes.

## Setup

Confirm your lab is up:

```bash
docker ps --filter "name=juice-shop"     # should show it running
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:3000   # expect 200
```

Open `http://localhost:3000` in a browser with dev tools open (`F12` → **Network** tab). You're going to click through the app and *read the actual requests it makes* — this is the fastest way to draw an accurate DFD instead of a guessed one.

## Tasks

Work through each flow, recording the request(s) it fires in the Network tab, then draw.

1. **Register and log in.** Create an account, then log in with it. In the Network tab, find the request the login form sends. Note: the URL, the method, what's in the request body, and what comes back in the response (look for a token).

2. **Browse products.** Use the search box. Find the request it fires. Note whether it requires you to be logged in (try it logged out, in an incognito window, to check).

3. **Add to basket and check out.** While logged in, add a product to your basket and proceed through checkout as far as you comfortably can. Find the request(s) for adding an item and for checkout. Note what data travels in each.

4. **Try to reach the admin panel.** Navigate to `/#/administration` both logged out and logged in as your regular (non-admin) account. Note what happens in each case — does the client stop you, does the server, or does it let you in?

5. **Draw the DFD.** Using the four element types from Lecture 1 (external entity, process, data store, data flow), draw your diagram as a Mermaid `flowchart`. Include:
   - At least one external entity (your browser / a customer).
   - A process for each of the four flows above (you may combine closely related requests into one process if that matches what you observed).
   - At least three data stores (users, products, baskets/orders — infer these from what each response returns, even though you can't see the database directly).
   - Every data flow, labeled with what actually travels (not just "data").
   - **All trust boundaries** — mark at minimum the network edge and the authentication boundary; add the authorization boundary around the admin process if your observation in Task 4 supports one existing.

6. **Write one paragraph** describing one thing you observed in the Network tab that *surprised* you or that you wouldn't have guessed just from reading Lecture 1's version of this diagram.

## Deliverable

A file `dfd.md` containing:
- Your Mermaid diagram (as a fenced ` ```mermaid ` code block).
- The Task 6 paragraph.
- A short list of the actual request URLs/methods you observed for each of the four flows (this is your evidence — the diagram should be traceable back to these).

## Done when…

- [ ] Your diagram has all four element types, correctly shaped/typed (no data flow connects two data stores directly).
- [ ] Every arrow has a label naming the actual data, not a generic placeholder.
- [ ] At least two trust boundaries are drawn and named.
- [ ] Your diagram reflects what you *observed* in the Network tab, not a guess — the request-list section proves it.
- [ ] Task 4's observation (does the server actually block a non-admin, or only the client-side UI?) is recorded — you'll need this exact fact in Exercise 2.

## Stretch

- Add a Level 2 explosion of just the login process (parse request → look up user → verify password → issue token), and mark which of *those* sub-steps is where you'd expect the highest-risk threat to live, before you've run STRIDE on it.
- Note one flow you couldn't fully observe from the Network tab alone (e.g., what the server does internally after receiving a request) and what additional information (source code, docs) would resolve it.

## Submission

Keep `dfd.md` in `week-02-exercises/exercise-01/` in your portfolio. Exercise 2 uses this diagram directly.
