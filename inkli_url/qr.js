const express = require('express');
const QRCode = require('qrcode');
const router = express.Router();

router.get('/', async (req, res) => {
  const url = req.query.url;

  if (!url) {
    return res.status(400).json({ error: 'Please provide a "url" query parameter.' });
  }

  try {
    const qrCodeDataUrl = await QRCode.toDataURL(url);
    res.json({ qrCode: qrCodeDataUrl });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error generating QR code' });
  }
});

module.exports = router;