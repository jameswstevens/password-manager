const express = require('express');
const bodyParser = require('body-parser');
const { Keychain } = require('./password-manager');

const app = express();
app.use(bodyParser.json());
app.use(express.static('public'));

let keychain;

app.post('/init', async (req, res) => {
    const { password } = req.body;
    try {
        keychain = await Keychain.init(password);
        res.status(200).send('Keychain initialized');
    } catch (error) {
        res.status(500).send('Error initializing keychain');
    }
});

app.post('/set', async (req, res) => {
    const { name, value } = req.body;
    try {
        await keychain.set(name, value);
        res.status(200).send('Password set');
    } catch (error) {
        res.status(500).send('Error setting password');
    }
});

app.get('/get', async (req, res) => {
    const { name } = req.query;
    try {
        const password = await keychain.get(name);
        if (password) {
            res.status(200).send(password);
        } else {
            res.status(404).send('Password not found');
        }
    } catch (error) {
        res.status(500).send('Error retrieving password');
    }
});

app.delete('/remove', async (req, res) => {
    const { name } = req.body;
    try {
        const result = await keychain.remove(name);
        if (result) {
            res.status(200).send('Password removed');
        } else {
            res.status(404).send('Password not found');
        }
    } catch (error) {
        res.status(500).send('Error removing password');
    }
});

app.get('/dump', async (req, res) => {
    try {
        const data = await keychain.dump();
        res.status(200).json(data);
    } catch (error) {
        res.status(500).send('Error dumping database');
    }
});

app.post('/load', async (req, res) => {
    const { password, repr, trustedDataCheck } = req.body;
    try {
        keychain = await Keychain.load(password, repr, trustedDataCheck);
        res.status(200).send('Keychain loaded');
    } catch (error) {
        res.status(500).send('Error loading keychain');
    }
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});