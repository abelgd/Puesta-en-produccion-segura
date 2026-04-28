const router = require('express').Router();
const auth = require('../middleware/auth');
const ctrl = require('../controllers/auth.controller');

router.post('/register', ctrl.register);
router.post('/login', ctrl.login);
router.get('/profile', auth, ctrl.getProfile);
router.get('/github', ctrl.githubLogin);
router.get('/github/callback', ctrl.githubCallback);

module.exports = router;