Sports Scheduler rManagement Web Application

This is a web-based Sports Management System developed using Node.js and Express.js. It enables both administrators and players to interact with the platform, offering various functionalities to manage sports and sessions.

Key Features:

User Authentication & Authorization: Users can register as either administrators or players and log in securely. Administrators can access a dashboard for managing sports and sessions, while players can view and join available sessions.
CRUD Operations: Administrators have the capability to create, update, and delete sports and sessions to maintain up-to-date offerings.
Session Management: Players can browse through scheduled sessions and join the ones that are available. The system ensures that session team size constraints are respected.
CSRF Protection: The platform employs CSRF protection to secure users against malicious attacks.
Secure Password Storage: User passwords are hashed and stored securely using bcrypt for enhanced security.
