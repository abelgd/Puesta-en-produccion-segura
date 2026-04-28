const router = require('express').Router();
const ctrl = require('../controllers/adoptions.controller');
const auth = require('../middleware/auth');
const { checkRole } = require('../middleware/rbac'); // ← cambia esto

router.get('/pets', ctrl.getPets);
router.get('/', auth, ctrl.getAll);
router.post('/', auth, ctrl.adopt);
//router.post('/pets', auth, checkRole('admin'), ctrl.createPet); // ← y esto

module.exports = router;