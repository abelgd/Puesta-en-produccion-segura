const router = require('express').Router();
const auth = require('../middleware/auth');
const rbac = require('../middleware/rbac');
const ctrl = require('../controllers/products.controller');

router.get('/', ctrl.getAll);
router.get('/discounts', auth, ctrl.getWithDiscount); // ABAC aplicado en la vista
router.post('/', auth, rbac('admin','ventas'), ctrl.create);

module.exports = router;