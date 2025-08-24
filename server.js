// server.js (Versi Final dengan Integrasi Midtrans dan Logika Anti Double-Booking)

const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const validator = require('validator');
const crypto = require('crypto');

// --- [BARU] Import library Midtrans ---
const midtransClient = require('midtrans-client');

// --- [PENTING] Gunakan environment variables untuk kunci rahasia ---
require('dotenv').config();

const app = express();
const port = 3000;

// --- KONFIGURASI ---
const mongoUri = process.env.MONGO_URI;
const dbName = "databaseBooking";
const JWT_SECRET = process.env.JWT_SECRET;

// --- [BARU] Konfigurasi Midtrans ---
const MIDTRANS_SERVER_KEY = process.env.MIDTRANS_SERVER_KEY;
const MIDTRANS_CLIENT_KEY = process.env.MIDTRANS_CLIENT_KEY;

// Inisialisasi Midtrans Snap API
const snap = new midtransClient.Snap({
    isProduction: false,
    serverKey: MIDTRANS_SERVER_KEY,
    clientKey: MIDTRANS_CLIENT_KEY
});


let db;

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json());

const authUserMiddleware = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

const authAdminMiddleware = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err || !user.isAdmin) {
            return res.status(403).json({ message: "Akses ditolak. Hanya untuk admin." });
        }
        req.user = user;
        next();
    });
};

// --- KONEKSI DATABASE ---
MongoClient.connect(mongoUri)
    .then(async (client) => {
        console.log("✅ Berhasil terhubung ke MongoDB Atlas");
        db = client.db(dbName);
        
        await initializeDefaultSettings();

        app.listen(port, () => {
            console.log(`🚀 Backend server berjalan di http://localhost:${port}`);
        });
    })
    .catch(error => console.error("❌ Gagal terhubung ke MongoDB:", error));


// === FUNGSI HELPER & INISIALISASI ===
async function initializeDefaultSettings() {
    const settingsCollection = db.collection('settings');
    const count = await settingsCollection.countDocuments();
    if (count === 0) {
        console.log("🌱 Inisialisasi pengaturan jadwal default...");
        const defaultSettings = [];
        const days = ['Minggu', 'Senin', 'Selasa', 'Rabu', 'Kamis', 'Jumat', 'Sabtu'];
        for (let i = 0; i < 7; i++) {
            defaultSettings.push({
                dayOfWeek: i,
                dayName: days[i],
                isActive: true,
                openingHour: 8,
                closingHour: 22,
                basePrice: 20000,
                priceOverrides: [
                    { fromHour: 18, toHour: 22, price: 35000 }
                ]
            });
        }
        await settingsCollection.insertMany(defaultSettings);
        console.log("✅ Pengaturan default berhasil dibuat.");
    }
}

async function calculatePrice(playtime) {
    const targetDate = new Date(playtime.date);
    const dayOfWeek = targetDate.getUTCDay();
    const setting = await db.collection('settings').findOne({ dayOfWeek });
    if (!setting) throw new Error("Pengaturan jadwal tidak ditemukan");

    let price = setting.basePrice;
    if (setting.priceOverrides) {
        for (const override of setting.priceOverrides) {
            if (playtime.startHour >= override.fromHour && playtime.startHour < override.toHour) {
                price = override.price;
                break;
            }
        }
    }
    return price;
}


// === SHORTCUT UNTUK MEMBUAT ADMIN (HANYA UNTUK SETUP AWAL) ===
app.get('/api/setup/create-initial-admin', async (req, res) => {
    try {
        const adminEmail = "admin@binton.com";
        const existingAdmin = await db.collection('users').findOne({ email: adminEmail });
        if (existingAdmin) {
            return res.status(400).send('<h1>Akun admin sudah ada. Tidak perlu dibuat lagi.</h1><p>Silakan login dengan email: <strong>admin@binton.com</strong> dan password: <strong>passwordadmin123</strong></p>');
        }

        const adminData = {
            name: "Admin Binton",
            email: adminEmail,
            password: await bcrypt.hash("passwordadmin123", 12),
            phone: "08001234567",
            isAdmin: true,
            createdAt: new Date()
        };
        await db.collection('users').insertOne(adminData);
        
        console.log('✅ Akun admin berhasil dibuat!');
        res.status(201).send(`
            <h1>✅ Akun Admin Berhasil Dibuat!</h1>
            <p>Silakan login di aplikasi admin dengan detail berikut:</p>
            <ul>
                <li>Email: <strong>${adminEmail}</strong></li>
                <li>Password: <strong>passwordadmin123</strong></li>
            </ul>
            <p style="color:red;"><strong>PENTING:</strong> Setelah ini, hapus atau beri komentar pada endpoint ini di file server.js Anda demi keamanan.</p>
        `);
    } catch (error) {
        console.error("Gagal membuat admin:", error);
        res.status(500).send('<h1>Gagal membuat akun admin. Cek terminal backend.</h1>');
    }
});


// === ENDPOINTS UNTUK APLIKASI KLIEN ===

app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password, phone } = req.body;
        if (!validator.isEmail(email) || password.length < 6) return res.status(400).json({ message: 'Input tidak valid.' });
        const existingUser = await db.collection('users').findOne({ email });
        if (existingUser) return res.status(400).json({ message: 'Email sudah terdaftar.' });
        const hashedPassword = await bcrypt.hash(password, 12);
        await db.collection('users').insertOne({ name, email, password: hashedPassword, phone, isAdmin: false, createdAt: new Date() });
        res.status(201).json({ message: 'Registrasi berhasil!' });
    } catch (error) { res.status(500).json({ message: 'Error server.' }); }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await db.collection('users').findOne({ email });
        if (!user) return res.status(401).json({ message: 'Email atau password salah.' });
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ message: 'Email atau password salah.' });
        const token = jwt.sign({ userId: user._id, email: user.email, isAdmin: user.isAdmin || false }, JWT_SECRET, { expiresIn: '1d' });
        res.json({ token, user: { id: user._id, name: user.name, email: user.email, phone: user.phone, isAdmin: user.isAdmin || false } });
    } catch (error) { res.status(500).json({ message: 'Error server.' }); }
});

// =========================================================================
// ======================== [PERUBAHAN PERTAMA] ============================
// =========================================================================
app.get('/api/schedule', authUserMiddleware, async (req, res) => {
    const { date } = req.query;
    if (!date) return res.status(400).json({ message: "Parameter 'date' dibutuhkan" });

    try {
        const targetDate = new Date(date + "T00:00:00.000Z");
        const dayOfWeek = targetDate.getUTCDay();

        const setting = await db.collection('settings').findOne({ dayOfWeek: dayOfWeek });
        if (!setting || !setting.isActive) {
            return res.status(200).json({ message: "Tutup pada hari ini.", courts: [] });
        }

        let event = await db.collection('events').findOne({ date: targetDate });
        
        let openingHour = event?.openingHour ?? setting.openingHour;
        let closingHour = event?.closingHour ?? setting.closingHour;

        if (event && event.isClosed) {
            return res.status(200).json({ message: `Tutup: ${event.reason}`, courts: [] });
        }

        // --- [FIXED] Hanya mencari order yang statusnya 'paid' ---
        const regularBookings = await db.collection('orders').find({ 
            'playtimes.date': targetDate,
            'orderStatus': 'paid' // <-- HANYA CEK STATUS 'paid'
        }).toArray();
        
        const memberBookings = await db.collection('memberships').find({ recurringDay: dayOfWeek }).toArray();

        const bookedSlots = new Set();
        regularBookings.forEach(order => {
            order.playtimes.forEach(pt => {
                bookedSlots.add(`${pt.courtName}-${pt.startHour}`);
            });
        });
        memberBookings.forEach(member => {
            bookedSlots.add(`${member.courtName}-${member.recurringHour}`);
        });

        const courtNames = ["A", "B", "C"];
        const finalSchedule = courtNames.map(name => {
            const playtimes = [];
            for (let hour = openingHour; hour < closingHour; hour++) {
                const isBooked = bookedSlots.has(`${name}-${hour}`);
                
                let price = setting.basePrice;
                if (setting.priceOverrides) {
                    for (const override of setting.priceOverrides) {
                        if (hour >= override.fromHour && hour < override.toHour) {
                            price = override.price;
                            break;
                        }
                    }
                }

                playtimes.push({
                    _id: new ObjectId(),
                    start: `${hour.toString().padStart(2, '0')}:00`,
                    end: `${(hour + 1).toString().padStart(2, '0')}:00`,
                    status: isBooked ? 0 : 1,
                    price: price,
                    date: targetDate,
                    startHour: hour,
                    courtName: name,
                });
            }
            return { _id: new ObjectId(), name: name, playtimes: playtimes };
        });

        res.status(200).json({ message: "Jadwal tersedia", courts: finalSchedule });

    } catch (error) {
        console.error("Error get schedule:", error);
        res.status(500).json({ message: "Terjadi kesalahan pada server" });
    }
});

app.post('/api/orders', authUserMiddleware, async (req, res) => {
    const { playtimes } = req.body;
    const userId = new ObjectId(req.user.userId);
    const userEmail = req.user.email;

    if (!playtimes || playtimes.length === 0) {
        return res.status(400).json({ message: "Pilih minimal satu jadwal." });
    }

    try {
        let serverTotal = 0;
        const validatedPlaytimes = [];
        const item_details = [];

        for (const pt of playtimes) {
            const price = await calculatePrice(pt);
            serverTotal += price;
            validatedPlaytimes.push({
                courtName: pt.courtName,
                date: new Date(pt.date),
                startHour: pt.startHour,
                price: price
            });
            item_details.push({
                id: `${pt.courtName}-${pt.startHour}-${new Date(pt.date).getTime()}`,
                price: price,
                quantity: 1,
                name: `Booking Lap. ${pt.courtName} jam ${pt.startHour}:00`
            });
        }

        const orderId = `BINTON-${new ObjectId()}`;
        const newOrder = {
            _id: orderId,
            userId,
            playtimes: validatedPlaytimes,
            total: serverTotal,
            orderStatus: 'pending',
            createdAt: new Date()
        };
        await db.collection('orders').insertOne(newOrder);

        const parameter = {
            transaction_details: {
                order_id: orderId,
                gross_amount: serverTotal
            },
            customer_details: {
                email: userEmail,
            },
            item_details: item_details,
            callbacks: {
                finish: "https://your-frontend-app.com/payment-success"
            }
        };

        const transaction = await snap.createTransaction(parameter);
        const transactionToken = transaction.token;

        res.status(201).json({ 
            message: "Transaksi berhasil dibuat. Silakan selesaikan pembayaran.",
            transactionToken,
            orderId: orderId
        });

    } catch (error) {
        console.error("Booking Error:", error);
        res.status(500).json({ message: "Gagal memproses booking." });
    }
});


// =========================================================================
// ======================== [PERUBAHAN KEDUA] ==============================
// =========================================================================
app.post('/api/payment-notification', async (req, res) => {
    const notificationJson = req.body;

    try {
        // 1. Verifikasi notifikasi dari Midtrans
        const statusResponse = await snap.transaction.notification(notificationJson);
        const orderId = statusResponse.order_id;
        const transactionStatus = statusResponse.transaction_status;
        const fraudStatus = statusResponse.fraud_status;

        console.log(`🔔 Notifikasi diterima untuk Order ID: ${orderId} | Status: ${transactionStatus} | Fraud: ${fraudStatus}`);

        // 2. Cari order di database kita
        const order = await db.collection('orders').findOne({ _id: orderId });
        if (!order) {
            console.error(`❌ Order ${orderId} tidak ditemukan.`);
            return res.status(404).send("Order not found.");
        }
        
        // 3. Jika order sudah diproses (misal: sudah 'paid' atau 'failed'), jangan proses lagi
        if (order.orderStatus === 'paid' || order.orderStatus === 'failed') {
            console.log(`⏩ Order ${orderId} sudah pernah diproses. Status saat ini: ${order.orderStatus}. Notifikasi diabaikan.`);
            return res.status(200).send("Notification already processed.");
        }

        // 4. Logika utama "First to Pay Wins"
        let newStatus = order.orderStatus; // Default status tidak berubah

        // Cek apakah transaksi SUKSES
        const isSuccess = (transactionStatus == 'capture' && fraudStatus == 'accept') || transactionStatus == 'settlement';

        if (isSuccess) {
            // Transaksi berhasil, SEKARANG kita cek ketersediaan slot
            let isSlotAvailable = true;
            for (const pt of order.playtimes) {
                const existingPaidOrder = await db.collection('orders').findOne({
                    _id: { $ne: orderId }, // Cari di order lain
                    'orderStatus': 'paid',  // Yang statusnya sudah lunas
                    'playtimes': {
                        $elemMatch: { // Cek apakah ada playtime yang cocok
                            'courtName': pt.courtName,
                            'date': new Date(pt.date),
                            'startHour': pt.startHour
                        }
                    }
                });

                if (existingPaidOrder) {
                    // Ternyata slot sudah diambil orang lain!
                    isSlotAvailable = false;
                    console.warn(`⚔️ KONFLIK! Slot ${pt.courtName} @ ${pt.startHour} untuk order ${orderId} sudah di-booking oleh order ${existingPaidOrder._id}.`);
                    break; // Hentikan pengecekan
                }
            }

            if (isSlotAvailable) {
                // AMAN! Pengguna ini yang pertama membayar.
                newStatus = 'paid';
                console.log(`✅ Kemenangan! Semua slot untuk order ${orderId} tersedia. Status diubah menjadi 'paid'.`);
            } else {
                // KALAH! Slot sudah diambil.
                newStatus = 'failed'; // Tandai sebagai gagal
                console.error(`❌ Kalah Balapan! Order ${orderId} gagal karena slot sudah dipesan. Status diubah menjadi 'failed'.`);
                // Di dunia nyata, Anda akan memicu proses refund di sini.
            }

        } else if (transactionStatus == 'cancel' || transactionStatus == 'deny' || transactionStatus == 'expire') {
            // Transaksi GAGAL dari sisi Midtrans
            newStatus = 'failed';
        } else if (transactionStatus == 'pending') {
            // Transaksi masih PENDING
            newStatus = 'pending';
        }

        // 5. Update status order di database JIKA ada perubahan
        if (newStatus !== order.orderStatus) {
            await db.collection('orders').updateOne(
                { _id: orderId },
                { $set: { orderStatus: newStatus, paymentResponse: statusResponse } }
            );
            console.log(`💾 Status order ${orderId} berhasil diupdate dari '${order.orderStatus}' menjadi '${newStatus}'.`);
        }

        res.status(200).send("Notification received successfully.");

    } catch (error) {
        console.error("❌ Gagal memproses notifikasi Midtrans:", error.message);
        res.status(500).send("Internal Server Error");
    }
});



// === ENDPOINTS UNTUK APLIKASI ADMIN ===

app.get('/api/admin/settings', authAdminMiddleware, async (req, res) => {
    try {
        const settings = await db.collection('settings').find().sort({ dayOfWeek: 1 }).toArray();
        res.json(settings);
    } catch (error) { res.status(500).json({ message: 'Error server.' }); }
});

app.put('/api/admin/settings', authAdminMiddleware, async (req, res) => {
    try {
        const updatedSettings = req.body;
        for (const setting of updatedSettings) {
            const { _id, ...dataToUpdate } = setting;
            await db.collection('settings').updateOne({ _id: new ObjectId(_id) }, { $set: dataToUpdate });
        }
        res.json({ message: 'Pengaturan berhasil diperbarui.' });
    } catch (error) { res.status(500).json({ message: 'Gagal memperbarui pengaturan.' }); }
});

app.get('/api/admin/events', authAdminMiddleware, async (req, res) => {
    try {
        const events = await db.collection('events').find().toArray();
        res.json(events);
    } catch (error) { res.status(500).json({ message: 'Error server.' }); }
});

app.post('/api/admin/events', authAdminMiddleware, async (req, res) => {
    try {
        const eventData = req.body;
        eventData.date = new Date(eventData.date + "T00:00:00.000Z");
        await db.collection('events').deleteOne({ date: eventData.date });
        await db.collection('events').insertOne(eventData);
        res.status(201).json({ message: 'Event berhasil dibuat.' });
    } catch (error) { res.status(500).json({ message: 'Gagal membuat event.' }); }
});

app.get('/api/admin/memberships', authAdminMiddleware, async (req, res) => {
    try {
        const members = await db.collection('memberships').find().toArray();
        res.json(members);
    } catch (error) { res.status(500).json({ message: 'Error server.' }); }
});

app.post('/api/admin/memberships', authAdminMiddleware, async (req, res) => {
    try {
        const memberData = req.body;
        await db.collection('memberships').insertOne(memberData);
        res.status(201).json({ message: 'Member berhasil ditambahkan.' });
    } catch (error) { res.status(500).json({ message: 'Gagal menambah member.' }); }
});

app.put('/api/admin/memberships/:id', authAdminMiddleware, async (req, res) => {
    try {
        const { id } = req.params;
        const { recurringDay, recurringHour, courtName } = req.body;
        await db.collection('memberships').updateOne(
            { _id: new ObjectId(id) },
            { $set: { recurringDay, recurringHour, courtName } }
        );
        res.json({ message: 'Jadwal member berhasil dipindahkan.' });
    } catch (error) { res.status(500).json({ message: 'Gagal memindahkan jadwal member.' }); }
});