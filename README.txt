Uddokta 360 - local server
1. Install Node.js 18+ (nodejs.org)
2. In this folder run:  npm start
3. Open the "Other devices" address it prints, on any phone/laptop on the same Wi-Fi.
4. First time: on the login page press "Set your password", choose a username, category and password.
   Next time just log in.
Data is saved in data.json and logins in users.json (back both files up).
Passwords are stored hashed (scrypt) in users.json, never as plain text.
Role management: the Managing Director sees a "Role management" page in the menu. There, each category
(Chairman, Managing Director, Marketing Head, R&D, Creative Head) has tick-boxes for every page.
Tick a page to show it to that category, untick to hide it. Choices are saved in roles.json (back it up too).
