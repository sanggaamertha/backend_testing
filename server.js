// server.js (Versi Final - Real-time dengan ID Slot Spesifik)

const express = require("express");
const http = require('http');
const { Server } = require("socket.io");
const { MongoClient, ObjectId } = require("mongodb");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const validator = require("validator");
const midtransClient = require("midtrans-client");
const { format } = require('date-fns');

require("dotenv").config();

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

const port = process.env.PORT || 3000;

// --- KONFIGURASI ---
const mongoUri = process.env.MONGO_URI;
const dbName = "databaseBooking";
const JWT_SECRET = process.env.JWT_SECRET;
const MIDTRANS_SERVER_KEY = process.env.MIDTRANS_SERVER_KEY;
const MIDTRANS_CLIENT_KEY = process.env.MIDTRANS_CLIENT_KEY;

const snap = new midtransClient.Snap({
  isProduction: false,
  serverKey: MIDTRANS_SERVER_KEY,
  clientKey: MIDTRANS_CLIENT_KEY,
});

let db;
app.set('socketio', io);

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json());

const authUserMiddleware = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) return res.sendStatus(401);
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

const authAdminMiddleware = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
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
    server.listen(port, () => {
      console.log(`🚀 Backend server & Socket.IO berjalan di http://localhost:${port}`);
    });
  })
  .catch((error) => console.error("❌ Gagal terhubung ke MongoDB:", error));

// --- LOGIKA KONEKSI SOCKET.IO ---
io.on('connection', (socket) => {
  console.log('🔌 Klien baru terhubung:', socket.id);
  socket.on('disconnect', () => {
    console.log('🔌 Klien terputus:', socket.id);
  });
});

// === FUNGSI HELPER & INISIALISASI ===
async function initializeDefaultSettings() {
  const settingsCollection = db.collection("settings");
  const count = await settingsCollection.countDocuments();
  if (count === 0) {
    console.log("🌱 Inisialisasi pengaturan jadwal default...");
    const defaultSettings = [];
    const days = ["Minggu", "Senin", "Selasa", "Rabu", "Kamis", "Jumat", "Sabtu"];
    for (let i = 0; i < 7; i++) {
      defaultSettings.push({
        dayOfWeek: i,
        dayName: days[i],
        isActive: true,
        openingHour: 8,
        closingHour: 22,
        basePrice: 20000,
        priceOverrides: [{ fromHour: 18, toHour: 22, price: 35000 }],
      });
    }
    await settingsCollection.insertMany(defaultSettings);
    console.log("✅ Pengaturan default berhasil dibuat.");
  }
}

async function calculatePrice(playtime) {
  const targetDate = new Date(playtime.date);
  const dayOfWeek = targetDate.getUTCDay();
  const setting = await db.collection("settings").findOne({ dayOfWeek });
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

// === ENDPOINTS UNTUK APLIKASI KLIEN ===

app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;
    if (!validator.isEmail(email) || password.length < 6)
      return res.status(400).json({ message: "Input tidak valid." });
    const existingUser = await db.collection("users").findOne({ email });
    if (existingUser)
      return res.status(400).json({ message: "Email sudah terdaftar." });
    const hashedPassword = await bcrypt.hash(password, 12);
    await db.collection("users").insertOne({ name, email, password: hashedPassword, phone, isAdmin: false, createdAt: new Date() });
    res.status(201).json({ message: "Registrasi berhasil!" });
  } catch (error) {
    res.status(500).json({ message: "Error server." });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await db.collection("users").findOne({ email });
    if (!user)
      return res.status(401).json({ message: "Email atau password salah." });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(401).json({ message: "Email atau password salah." });
    const token = jwt.sign({ userId: user._id, email: user.email, isAdmin: user.isAdmin || false }, JWT_SECRET, { expiresIn: "1d" });
    res.json({
      token,
      user: { id: user._id, name: user.name, email: user.email, phone: user.phone, isAdmin: user.isAdmin || false },
    });
  } catch (error) {
    res.status(500).json({ message: "Error server." });
  }
});

app.get("/api/schedule", authUserMiddleware, async (req, res) => {
  const { date } = req.query; // date is 'yyyy-MM-dd'
  if (!date) {
    return res.status(400).json({ message: "Parameter 'date' dibutuhkan" });
  }
  try {
    const targetDate = new Date(date + "T00:00:00.000Z");
    const dayOfWeek = targetDate.getUTCDay();

    const setting = await db.collection("settings").findOne({ dayOfWeek: dayOfWeek });
    if (!setting || !setting.isActive) {
      return res.status(200).json({ message: "Tutup pada hari ini.", courts: [] });
    }

    let event = await db.collection("events").findOne({ date: targetDate });
    let openingHour = event?.openingHour ?? setting.openingHour;
    let closingHour = event?.closingHour ?? setting.closingHour;

    if (event && event.isClosed) {
      return res.status(200).json({ message: `Tutup: ${event.reason}`, courts: [] });
    }

    const tenMinutesAgo = new Date(Date.now() - 10 * 60 * 1000);
    const bookings = await db.collection("orders").find({
      "playtimes.date": targetDate,
      $or: [
        { orderStatus: "paid" },
        { orderStatus: "pending", createdAt: { $gte: tenMinutesAgo } }
      ]
    }).toArray();

    const memberBookings = await db.collection("memberships").find({ recurringDay: dayOfWeek }).toArray();

    const bookedSlots = new Map();

    bookings.forEach((order) => {
      order.playtimes.forEach((pt) => {
        const key = `${pt.courtName}-${pt.startHour}`;
        bookedSlots.set(key, order.orderStatus === 'paid' ? 0 : 2);
      });
    });

    memberBookings.forEach((member) => {
        const key = `${member.courtName}-${member.recurringHour}`;
        bookedSlots.set(key, 0);
    });

    const courtNames = ["A", "B", "C"];
    const finalSchedule = courtNames.map((name) => {
      const playtimes = [];
      for (let hour = openingHour; hour < closingHour; hour++) {
        const key = `${name}-${hour}`;
        const slotStatus = bookedSlots.get(key);

        let status = (slotStatus !== undefined) ? slotStatus : 1;
        
        let price = setting.basePrice;
        if (setting.priceOverrides) {
          for (const override of setting.priceOverrides) {
            if (hour >= override.fromHour && hour < override.toHour) {
              price = override.price;
              break;
            }
          }
        }

        const playtimeId = `${name}-${date}-${hour}`;

        playtimes.push({
          // --- [PERBAIKAN] Mengembalikan properti ke _id ---
          _id: playtimeId, 
          start: `${hour.toString().padStart(2, "0")}:00`,
          end: `${(hour + 1).toString().padStart(2, "0")}:00`,
          status: status,
          price: price,
          date: targetDate,
          startHour: hour,
          courtName: name,
        });
      }
      // --- [PERBAIKAN] Mengembalikan properti ke _id ---
      return { _id: new ObjectId(), name: name, playtimes: playtimes };
    });
    res.status(200).json({ message: "Jadwal tersedia", courts: finalSchedule });
  } catch (error) {
    console.error("Error get schedule:", error);
    res.status(500).json({ message: "Terjadi kesalahan pada server" });
  }
});


app.post("/api/orders", authUserMiddleware, async (req, res) => {
  const { playtimes } = req.body;
  const userId = new ObjectId(req.user.userId);
  const userEmail = req.user.email;
  if (!playtimes || playtimes.length === 0) {
    return res.status(400).json({ message: "Pilih minimal satu jadwal." });
  }
  
  try {
    for (const pt of playtimes) {
      const targetDate = new Date(pt.date);
      const tenMinutesAgo = new Date(Date.now() - 10 * 60 * 1000);
      const existingOrder = await db.collection("orders").findOne({
          "playtimes": { 
              $elemMatch: { 
                  courtName: pt.courtName, 
                  date: targetDate, 
                  startHour: pt.startHour 
              } 
          },
          $or: [
              { "orderStatus": "paid" },
              { "orderStatus": "pending", "createdAt": { $gte: tenMinutesAgo } }
          ]
      });

      if (existingOrder) {
          const message = existingOrder.orderStatus === 'paid' 
              ? `Jadwal ${pt.courtName} jam ${pt.startHour}:00 sudah tidak tersedia.`
              : `Jadwal ${pt.courtName} jam ${pt.startHour}:00 sedang dalam proses booking oleh orang lain.`;
          return res.status(409).json({ message });
      }
    }
    
    let serverTotal = 0;
    const validatedPlaytimes = [];
    const item_details = [];

    const bookingDate = format(new Date(playtimes[0].date), 'yyyy-MM-dd');

    for (const pt of playtimes) {
      const price = await calculatePrice(pt);
      serverTotal += price;
      validatedPlaytimes.push({ courtName: pt.courtName, date: new Date(pt.date), startHour: pt.startHour, price: price });
      // --- [PERBAIKAN] ID untuk item midtrans tetap menggunakan format yang sama ---
      const playtimeId = `${pt.courtName}-${bookingDate}-${pt.startHour}`;
      item_details.push({
        id: playtimeId,
        price: price,
        quantity: 1,
        name: `Booking Lap. ${pt.courtName} jam ${pt.startHour}:00`,
      });
    }

    const orderId = `BINTON-${new ObjectId()}`;
    const newOrder = { _id: orderId, userId, playtimes: validatedPlaytimes, total: serverTotal, orderStatus: 'pending', createdAt: new Date(), transactionToken: null };
    await db.collection('orders').insertOne(newOrder);

    const parameter = {
      transaction_details: { order_id: orderId, gross_amount: serverTotal },
      customer_details: { email: userEmail },
      item_details: item_details,
      expiry: { unit: "minute", duration: 10 }
    };
    const transaction = await snap.createTransaction(parameter);
    const transactionToken = transaction.token;
    await db.collection('orders').updateOne({ _id: orderId }, { $set: { transactionToken: transactionToken } });

    const updatedSlots = playtimes.map(pt => {
        return {
            // --- [PERBAIKAN] slotId di socket disamakan dengan _id di frontend ---
            slotId: `${pt.courtName}-${bookingDate}-${pt.startHour}`,
            newStatus: 2 // 2 = pending
        };
    });

    const socketIo = req.app.get('socketio');
    socketIo.emit('schedule_updated', { 
        date: bookingDate,
        slots: updatedSlots
    });
    console.log(`📢 Memancarkan 'schedule_updated' (pending) untuk tanggal: ${bookingDate} dengan slot:`, updatedSlots);

    res.status(201).json({
      message: "Transaksi berhasil dibuat. Selesaikan pembayaran dalam 10 menit.",
      transactionToken,
      orderId: orderId
    });
  } catch (error) {
    console.error("Booking Error:", error);
    res.status(500).json({ message: "Gagal memproses booking." });
  }
});


app.post('/api/payment-notification', async (req, res) => {
    const notificationJson = req.body;
    try {
        const statusResponse = await snap.transaction.notification(notificationJson);
        const orderId = statusResponse.order_id;
        const transactionStatus = statusResponse.transaction_status;
        const fraudStatus = statusResponse.fraud_status;
        const order = await db.collection('orders').findOne({ _id: orderId });

        if (!order || order.orderStatus === 'paid' || order.orderStatus === 'failed') {
            return res.status(200).send("Notification ignored: Order not found or already processed.");
        }

        let newStatus = order.orderStatus;
        let isSuccess = false;

        if ((transactionStatus == 'capture' && fraudStatus == 'accept') || transactionStatus == 'settlement') {
            newStatus = 'paid';
            isSuccess = true;
        } else if (['cancel', 'deny', 'expire'].includes(transactionStatus)) {
            newStatus = 'failed';
        }

        if (newStatus !== order.orderStatus) {
            await db.collection('orders').updateOne(
                { _id: orderId }, 
                { $set: { orderStatus: newStatus, paymentResponse: statusResponse } }
            );
            
            if (order.playtimes && order.playtimes.length > 0) {
                const bookingDate = format(new Date(order.playtimes[0].date), 'yyyy-MM-dd');
                const updatedSlots = order.playtimes.map(pt => {
                    const ptDate = format(new Date(pt.date), 'yyyy-MM-dd');
                    return {
                        // --- [PERBAIKAN] slotId di socket disamakan dengan _id di frontend ---
                        slotId: `${pt.courtName}-${ptDate}-${pt.startHour}`,
                        newStatus: isSuccess ? 0 : 1 // 0 = booked, 1 = available again
                    };
                });
                
                const socketIo = req.app.get('socketio');
                socketIo.emit('schedule_updated', { 
                    date: bookingDate,
                    slots: updatedSlots
                });
                console.log(`📢 Memancarkan 'schedule_updated' (notif) untuk tanggal: ${bookingDate} dengan status: ${newStatus}`, updatedSlots);
            }
        }
        res.status(200).send("Notification received successfully.");
    } catch (error) {
        console.error("Notification Error:", error)
        res.status(500).send("Internal Server Error");
    }
});

app.get("/api/orders/:orderId/resume-payment", authUserMiddleware, async (req, res) => {
    try {
      const { orderId } = req.params;
      const userId = new ObjectId(req.user.userId);
      const order = await db.collection("orders").findOne({ _id: orderId });
      if (!order) {
        return res.status(404).json({ message: "Pesanan tidak ditemukan." });
      }
      if (!order.userId.equals(userId)) {
        return res.status(403).json({ message: "Akses ditolak." });
      }
      if (order.orderStatus !== "pending") {
        return res.status(400).json({ message: `Pesanan ini sudah ${order.orderStatus}.` });
      }
      const now = new Date();
      const orderTime = new Date(order.createdAt);
      const diffInMinutes = (now - orderTime) / (1000 * 60);
      if (diffInMinutes > 10) {
        await db.collection("orders").updateOne({ _id: orderId }, { $set: { orderStatus: "failed" } });
        return res.status(410).json({ message: "Waktu pembayaran sudah habis." });
      }
      res.status(200).json({ transactionToken: order.transactionToken });
    } catch (error) {
      console.error("Resume Payment Error:", error);
      res.status(500).json({ message: "Gagal melanjutkan pembayaran." });
    }
});

app.get("/api/my-orders", authUserMiddleware, async (req, res) => {
  try {
    const userId = new ObjectId(req.user.userId);
    const orders = await db.collection("orders").find({ userId: userId }).sort({ createdAt: -1 }).toArray();
    res.status(200).json(orders);
  } catch (error) {
    res.status(500).json({ message: "Gagal mengambil data pesanan." });
  }
});

app.put("/api/profile", authUserMiddleware, async (req, res) => {
  try {
    const userId = new ObjectId(req.user.userId);
    const { name, phone } = req.body;
    if (!name || !phone)
      return res.status(400).json({ message: "Nama dan nomor telepon tidak boleh kosong." });
    await db.collection("users").updateOne({ _id: userId }, { $set: { name: name, phone: phone } });
    const updatedUser = await db.collection("users").findOne({ _id: userId }, { projection: { password: 0 } });
    updatedUser.id = updatedUser._id;
    delete updatedUser._id;
    res.status(200).json({ message: "Profil berhasil diperbarui.", user: updatedUser });
  } catch (error) {
    res.status(500).json({ message: "Gagal memperbarui profil." });
  }
});

// === ENDPOINTS UNTUK APLIKASI ADMIN ===
app.get("/api/admin/settings", authAdminMiddleware, async (req, res) => {
  try {
    const settings = await db.collection("settings").find().sort({ dayOfWeek: 1 }).toArray();
    res.json(settings);
  } catch (error) { res.status(500).json({ message: 'Error server.' }); }
});

app.put("/api/admin/settings", authAdminMiddleware, async (req, res) => {
  try {
    const updatedSettings = req.body;
    for (const setting of updatedSettings) {
      const { _id, ...dataToUpdate } = setting;
      await db.collection("settings").updateOne({ _id: new ObjectId(_id) }, { $set: dataToUpdate });
    }
    res.json({ message: 'Pengaturan berhasil diperbarui.' });
  } catch (error) { res.status(500).json({ message: 'Gagal memperbarui pengaturan.' }); }
});

app.get("/api/admin/events", authAdminMiddleware, async (req, res) => {
  try {
    const events = await db.collection("events").find().toArray();
    res.json(events);
  } catch (error) { res.status(500).json({ message: 'Error server.' }); }
});

app.post("/api/admin/events", authAdminMiddleware, async (req, res) => {
  try {
    const eventData = req.body;
    eventData.date = new Date(eventData.date + "T00:00:00.000Z");
    await db.collection("events").deleteOne({ date: eventData.date });
    await db.collection("events").insertOne(eventData);
    res.status(201).json({ message: 'Event berhasil dibuat.' });
  } catch (error) { res.status(500).json({ message: 'Gagal membuat event.' }); }
});

app.get("/api/admin/memberships", authAdminMiddleware, async (req, res) => {
  try {
    const members = await db.collection("memberships").find().toArray();
    res.json(members);
  } catch (error) { res.status(500).json({ message: 'Error server.' }); }
});

app.post("/api/admin/memberships", authAdminMiddleware, async (req, res) => {
  try {
    const memberData = req.body;
    await db.collection("memberships").insertOne(memberData);
    res.status(201).json({ message: 'Member berhasil ditambahkan.' });
  } catch (error) { res.status(500).json({ message: 'Gagal menambah member.' }); }
});

app.put("/api/admin/memberships/:id", authAdminMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { recurringDay, recurringHour, courtName } = req.body;
    await db.collection("memberships").updateOne(
        { _id: new ObjectId(id) },
        { $set: { recurringDay, recurringHour, courtName } }
    );
    res.json({ message: 'Jadwal member berhasil dipindahkan.' });
  } catch (error) { res.status(500).json({ message: 'Gagal memindahkan jadwal member.' }); }
});