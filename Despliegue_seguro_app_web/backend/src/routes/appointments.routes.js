const router = require('express').Router();
const auth = require('../middleware/auth');
const rbac = require('../middleware/rbac');
const ctrl = require('../controllers/appointments.controller');

router.get('/', auth, ctrl.getAll);
router.post('/', auth, rbac('admin', 'cliente', 'veterinario'), ctrl.create);
router.patch('/:id', auth, rbac('admin', 'veterinario'), ctrl.updateStatus);

module.exports = router;