const express = require('express');
const rbacController = require('../controllers/rbacController');
const { protect, authorize } = require('../middlewares/authMiddleware');

const router = express.Router();

router.use(protect);

router.post('/', authorize('user:create'), rbacController.create);
router.patch('/', authorize('user:update'), rbacController.update);
router.post('/delete', authorize('user:delete'), rbacController.delete);
router.get('/', authorize('user:view'), rbacController.getAllUsers);

module.exports = router;