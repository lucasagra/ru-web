const express = module.require('express');
const router = express.Router();
const path = module.require('path');
const puppeteer = module.require('puppeteer');

const middleware = module.require('../middlewares/middleware');

router.use((req, res, next) => {
    console.log(`[${Date.now()}] ${req.method} ${req.originalUrl}`);
    next();
});

router.get('/checar', (req, res) => {
    res.render('pages/home', {title: 'Homepage'});
});

router.post('/checar', middleware.checkUserData, (req, res) => {
    (async (username, password) => {
        const browser = await puppeteer.launch();

        const page = await browser.newPage();
        await page.goto('https://sistemas.ufal.br/academico/login.seam');

        await page.type('[id="loginForm:username"]', req.body.username);
        await page.type('[id="loginForm:password"]', req.body.password);
        await page.click('[id="loginForm:entrar"]');
        // await page.waitForNavigation();

        var url = page.url().split('?');

        await browser.close();

        if (url.length > 1) res.send('Logado.');
        else res.send('Login ou Senha Incorretos.');
    })();
});

module.exports = router;