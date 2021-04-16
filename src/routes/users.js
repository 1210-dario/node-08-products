const { Router } = require('express');
const {
    getAllUsers,
    createUser,
    updateUser,
    getById,
    deleteUser
} = require('../controllers/users');
const {
    postRequestValidations,
    putRequestValidations,
    getRequestValidation,
    deleteRequestValidation } = require('../middlewares/users');

const router = Router();

router.get('/', getAllUsers);
router.post('/', postRequestValidations, createUser);
router.put('/:id', putRequestValidations, updateUser);
router.get('/:id', getRequestValidation, getById);
router.delete('/:id', deleteRequestValidation, deleteUser);

module.exports = router;
