db.getSiblingDB('hack_ai_v2').createUser({
  user: 'are_app',
  pwd: process.env.MONGO_APP_PASSWORD,
  roles: [{ role: 'readWrite', db: 'hack_ai_v2' }]
});
