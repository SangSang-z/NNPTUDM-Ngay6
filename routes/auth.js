const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const userController = require('../controllers/users');
const User = require('../schemas/users');

const privateKey = fs.readFileSync(
  path.join(__dirname, '../keys/private.key'),
  'utf8'
);

const publicKey = fs.readFileSync(
  path.join(__dirname, '../keys/public.key'),
  'utf8'
);

// middleware kiểm tra token
function authMiddleware(req, res, next) {
  try {
    const authorization = req.headers.authorization;

    if (!authorization || !authorization.startsWith('Bearer ')) {
      return res.status(401).send({
        message: 'ban chua dang nhap'
      });
    }

    const token = authorization.split(' ')[1];

    const decoded = jwt.verify(token, publicKey, {
      algorithms: ['RS256']
    });

    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).send({
      message: 'token khong hop le'
    });
  }
}

// register
router.post('/register', async function (req, res) {
  try {
    let { username, password, email } = req.body;

    let newUser = await userController.CreateAnUser(
      username,
      password,
      email,
      '69b0ddec842e41e8160132b8'
    );

    res.send(newUser);
  } catch (error) {
    res.status(404).send({
      message: error.message
    });
  }
});

// login
router.post('/login', async function (req, res) {
  try {
    const { username, password } = req.body;

    const user = await User.findOne({ username: username });

    if (!user) {
      return res.status(404).send({
        message: 'thong tin dang nhap sai'
      });
    }

    if (!bcrypt.compareSync(password, user.password)) {
      return res.status(404).send({
        message: 'thong tin dang nhap sai'
      });
    }

    const token = jwt.sign(
      {
        id: user._id,
        username: user.username
      },
      privateKey,
      {
        algorithm: 'RS256',
        expiresIn: '1d'
      }
    );

    res.send({
      message: 'dang nhap thanh cong',
      token: token
    });
  } catch (error) {
    res.status(500).send({
      message: error.message
    });
  }
});

// /me
router.get('/me', authMiddleware, async function (req, res) {
  try {
    const user = await User.findById(req.user.id).select('-password');

    if (!user) {
      return res.status(404).send({
        message: 'khong tim thay nguoi dung'
      });
    }

    res.send(user);
  } catch (error) {
    res.status(500).send({
      message: error.message
    });
  }
});

module.exports = router;

router.post('/changepassword', authMiddleware, async function (req, res) {
  try {
    const { oldpassword, newpassword } = req.body;

    if (!oldpassword || !newpassword) {
      return res.status(400).send({
        message: 'vui long nhap day du oldpassword va newpassword'
      });
    }

    // validate newpassword
    if (newpassword.length < 6) {
      return res.status(400).send({
        message: 'newpassword phai co it nhat 6 ky tu'
      });
    }

    const hasLetter = /[A-Za-z]/.test(newpassword);
    const hasNumber = /[0-9]/.test(newpassword);

    if (!hasLetter || !hasNumber) {
      return res.status(400).send({
        message: 'newpassword phai co it nhat 1 chu cai va 1 chu so'
      });
    }

    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(404).send({
        message: 'khong tim thay nguoi dung'
      });
    }

    const isOldPasswordCorrect = bcrypt.compareSync(oldpassword, user.password);

    if (!isOldPasswordCorrect) {
      return res.status(400).send({
        message: 'oldpassword khong dung'
      });
    }

    if (oldpassword === newpassword) {
      return res.status(400).send({
        message: 'newpassword khong duoc trung voi oldpassword'
      });
    }

    user.password = bcrypt.hashSync(newpassword, 10);
    await user.save();

    res.send({
      message: 'doi mat khau thanh cong'
    });
  } catch (error) {
    res.status(500).send({
      message: error.message
    });
  }
});