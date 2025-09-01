// server.js (Versi Perbaikan Final dengan Dukungan Multi-Lapangan)

const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const { MongoClient, ObjectId } = require("mongodb");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const validator = require("validator");
const midtransClient = require("midtrans-client");
const { format } = require("date-fns");
const admin = require("firebase-admin");

require("dotenv").config();

// --- Inisialisasi Firebase Admin SDK ---
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
  },
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
app.set("socketio", io);

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
      return res
        .status(403)
        .json({ message: "Akses ditolak. Hanya untuk admin." });
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
    // Inisialisasi data default yang baru
    await initializeDefaultData();
    setInterval(cleanupExpiredOrders, 60 * 1000);
    console.log("⏰ Robot pembersih pesanan kedaluwarsa telah aktif.");

    server.listen(port, () => {
      console.log(
        `🚀 Backend server & Socket.IO berjalan di http://localhost:${port}`
      );
    });
  })
  .catch((error) => console.error("❌ Gagal terhubung ke MongoDB:", error));

// --- LOGIKA KONEKSI SOCKET.IO ---
io.on("connection", (socket) => {
  console.log("🔌 Klien baru terhubung:", socket.id);
  socket.on("disconnect", () => {
    console.log("🔌 Klien terputus:", socket.id);
  });
});

// === ENDPOINTS AUTENTIKASI (TIDAK BERUBAH) ===
// ... (Endpoint /api/auth/google-signin, /register, /login tetap sama)
app.post("/api/auth/google-signin", async (req, res) => {
  const { idToken } = req.body;
  if (!idToken) {
    return res.status(400).json({ message: "ID Token tidak ditemukan." });
  }

  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const { uid, email, name } = decodedToken;
    let user = await db.collection("users").findOne({ email });

    if (!user) {
      const newUser = {
        name: name || "Pengguna Google",
        email,
        phone: decodedToken.phone_number || "",
        firebaseUid: uid,
        isAdmin: false,
        createdAt: new Date(),
      };
      const result = await db.collection("users").insertOne(newUser);
      user = { ...newUser, _id: result.insertedId };
    }
    const customToken = jwt.sign(
      { userId: user._id, email: user.email, isAdmin: user.isAdmin || false },
      JWT_SECRET,
      { expiresIn: "1d" }
    );
    res.json({
      token: customToken,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        isAdmin: user.isAdmin || false,
      },
    });
  } catch (error) {
    console.error("Error saat verifikasi Google Sign-In:", error);
    res
      .status(401)
      .json({ message: "Autentikasi Google gagal. Token tidak valid." });
  }
});

app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;
    if (!validator.isEmail(email) || password.length < 6)
      return res.status(400).json({ message: "Input tidak valid." });
    const existingUser = await db.collection("users").findOne({ email });
    if (existingUser)
      return res.status(400).json({ message: "Email sudah terdaftar." });
    const hashedPassword = await bcrypt.hash(password, 12);
    await db
      .collection("users")
      .insertOne({
        name,
        email,
        password: hashedPassword,
        phone,
        isAdmin: false,
        createdAt: new Date(),
      });
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

    if (!user.password) {
      return res
        .status(401)
        .json({
          message:
            "Akun ini terdaftar melalui Google. Silakan masuk dengan Google.",
        });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(401).json({ message: "Email atau password salah." });

    const token = jwt.sign(
      { userId: user._id, email: user.email, isAdmin: user.isAdmin || false },
      JWT_SECRET,
      { expiresIn: "1d" }
    );
    res.json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        isAdmin: user.isAdmin || false,
      },
    });
  } catch (error) {
    res.status(500).json({ message: "Error server." });
  }
});


// === [BARU] FUNGSI HELPER & INISIALISASI ===
async function initializeDefaultData() {
  const courtsCollection = db.collection("courts");
  const settingsCollection = db.collection("settings");
  const courtsCount = await courtsCollection.countDocuments();

  // Hanya jalankan jika koleksi courts kosong
  if (courtsCount === 0) {
    console.log("🌱 Inisialisasi data lapangan dan jadwal default...");

    // 1. Buat beberapa lapangan default
    const defaultCourts = [
      { name: "Lapangan A", description: "Lantai Vinyl", createdAt: new Date() },
      { name: "Lapangan B", description: "Lantai Sintetis", createdAt: new Date() },
      { name: "Lapangan C", description: "Lantai 2 (Ekonomi)", createdAt: new Date() },
    ];
    const insertedCourts = await courtsCollection.insertMany(defaultCourts);
    console.log(`✅ ${insertedCourts.insertedCount} lapangan default berhasil dibuat.`);

    // 2. Buat jadwal default untuk SETIAP lapangan yang baru dibuat
    const days = ["Minggu", "Senin", "Selasa", "Rabu", "Kamis", "Jumat", "Sabtu"];
    let settingsToInsert = [];

    for (const courtId of Object.values(insertedCourts.insertedIds)) {
        const court = await courtsCollection.findOne({_id: courtId});
        // Tentukan harga dasar berdasarkan nama lapangan untuk contoh
        let basePrice = 25000;
        if (court.name.includes("B")) basePrice = 30000;
        if (court.name.includes("C")) basePrice = 20000;

      for (let i = 0; i < 7; i++) {
        settingsToInsert.push({
          courtId: courtId, // Tautkan ke lapangan
          dayOfWeek: i,
          dayName: days[i],
          isActive: true,
          openingHour: 8,
          closingHour: 23,
          basePrice: basePrice,
          priceOverrides: [{ fromHour: 18, toHour: 23, price: basePrice + 15000 }],
        });
      }
    }
    await settingsCollection.insertMany(settingsToInsert);
    console.log("✅ Pengaturan jadwal default untuk semua lapangan berhasil dibuat.");
  }
}

async function calculatePrice(playtime) {
  const targetDate = new Date(playtime.date);
  const dayOfWeek = targetDate.getUTCDay();
  // Cari setting berdasarkan courtId dan dayOfWeek
  const setting = await db.collection("settings").findOne({
      courtId: new ObjectId(playtime.courtId),
      dayOfWeek
  });
  if (!setting) throw new Error("Pengaturan jadwal tidak ditemukan untuk lapangan ini");
  let price = setting.basePrice;
  if (setting.priceOverrides) {
    for (const override of setting.priceOverrides) {
      if (
        playtime.startHour >= override.fromHour &&
        playtime.startHour < override.toHour
      ) {
        price = override.price;
        break;
      }
    }
  }
  return price;
}

async function cleanupExpiredOrders() {
    try {
        const tenMinutesAgo = new Date(Date.now() - 10 * 60 * 1000);
        const result = await db.collection("orders").updateMany(
            { orderStatus: "pending", createdAt: { $lt: tenMinutesAgo } },
            { $set: { orderStatus: "failed" } }
        );
        if (result.modifiedCount > 0) {
            console.log(`🧹 Berhasil membersihkan ${result.modifiedCount} pesanan yang kedaluwarsa.`);
        }
    } catch (error) {
        console.error("❌ Error saat membersihkan pesanan kedaluwarsa:", error);
    }
}


// === [DIROMBAK] ENDPOINT UNTUK APLIKASI KLIEN ===

app.get("/api/schedule", authUserMiddleware, async (req, res) => {
  const { date } = req.query; // date is 'yyyy-MM-dd'
  if (!date) {
    return res.status(400).json({ message: "Parameter 'date' dibutuhkan" });
  }
  try {
    const targetDate = new Date(date + "T00:00:00.000Z");
    const dayOfWeek = targetDate.getUTCDay();

    // 1. Ambil semua data lapangan
    const allCourts = await db.collection("courts").find().sort({name: 1}).toArray();
    if (allCourts.length === 0) {
        return res.status(200).json({ message: "Tidak ada lapangan yang tersedia.", courts: [] });
    }

    // 2. Cek event global
    let event = await db.collection("events").findOne({ date: targetDate });
    if (event && event.isClosed) {
      return res.status(200).json({ message: `Tutup: ${event.reason}`, courts: [] });
    }

    // 3. Ambil semua booking yang relevan pada hari itu
    const tenMinutesAgo = new Date(Date.now() - 10 * 60 * 1000);
    const bookings = await db.collection("orders").find({
        "playtimes.date": targetDate,
        $or: [
          { orderStatus: "paid" },
          { orderStatus: "pending", createdAt: { $gte: tenMinutesAgo } },
        ],
      }).toArray();
    
    // 4. Ambil semua booking member yang relevan
    const memberBookings = await db.collection("memberships").find({ recurringDay: dayOfWeek }).toArray();

    // 5. Proses setiap lapangan
    let finalSchedule = [];

    for(const court of allCourts) {
        const courtSetting = await db.collection("settings").findOne({ courtId: court._id, dayOfWeek: dayOfWeek });
        
        if (!courtSetting || !courtSetting.isActive) {
            // Jika lapangan ini tutup, lewati
            continue;
        }

        let openingHour = event?.openingHour ?? courtSetting.openingHour;
        let closingHour = event?.closingHour ?? courtSetting.closingHour;

        const bookedSlots = new Map();

        // Filter booking untuk lapangan ini saja
        bookings.forEach((order) => {
            order.playtimes.forEach((pt) => {
                if(pt.courtId.equals(court._id)) {
                    const key = `${pt.courtName}-${pt.startHour}`;
                    bookedSlots.set(key, order.orderStatus === "paid" ? 0 : 2);
                }
            });
        });

        // Filter booking member untuk lapangan ini saja
        memberBookings.forEach((member) => {
             if(member.courtId.equals(court._id)) {
                const key = `${member.courtName}-${member.recurringHour}`;
                bookedSlots.set(key, 0);
             }
        });
        
        const playtimes = [];
        for (let hour = openingHour; hour < closingHour; hour++) {
            const key = `${court.name}-${hour}`;
            const slotStatus = bookedSlots.get(key);
            let status = slotStatus !== undefined ? slotStatus : 1;

            let price = courtSetting.basePrice;
            if (courtSetting.priceOverrides) {
                for (const override of courtSetting.priceOverrides) {
                    if (hour >= override.fromHour && hour < override.toHour) {
                        price = override.price;
                        break;
                    }
                }
            }

            const playtimeId = `${court._id}-${date}-${hour}`;

            playtimes.push({
                _id: playtimeId,
                start: `${hour.toString().padStart(2, "0")}:00`,
                end: `${(hour + 1).toString().padStart(2, "0")}:00`,
                status: status,
                price: price,
                date: targetDate,
                startHour: hour,
                courtName: court.name,
                courtId: court._id, // Sertakan courtId
            });
        }
        finalSchedule.push({ 
            _id: court._id, 
            name: court.name, 
            description: court.description,
            playtimes: playtimes 
        });
    }

    res.status(200).json({ message: "Jadwal tersedia", courts: finalSchedule });
  } catch (error) {
    console.error("Error get schedule:", error);
    res.status(500).json({ message: "Terjadi kesalahan pada server" });
  }
});

app.post("/api/orders", authUserMiddleware, async (req, res) => {
    // Pastikan `playtimes` memiliki `courtId`
    const { playtimes } = req.body;
    const userId = new ObjectId(req.user.userId);
    const userEmail = req.user.email;

    if (!playtimes || playtimes.length === 0) {
        return res.status(400).json({ message: "Pilih minimal satu jadwal." });
    }

    try {
        // ... (validasi waktu & ketersediaan slot tetap sama, tapi sekarang perlu cek `courtId`)
        const now = new Date();
        for (const pt of playtimes) {
            const slotTime = new Date(new Date(pt.date).setHours(pt.startHour, 0, 0, 0));
            if (now > slotTime) {
                return res.status(400).json({ message: `Waktu untuk slot ${pt.courtName} jam ${pt.startHour}:00 sudah lewat.` });
            }
        }
        for (const pt of playtimes) {
            const targetDate = new Date(pt.date);
            const tenMinutesAgo = new Date(Date.now() - 10 * 60 * 1000);
            const existingOrder = await db.collection("orders").findOne({
                "playtimes": {
                    $elemMatch: {
                        courtId: new ObjectId(pt.courtId),
                        date: targetDate,
                        startHour: pt.startHour
                    }
                },
                $or: [
                    { orderStatus: "paid" },
                    { orderStatus: "pending", createdAt: { $gte: tenMinutesAgo } }
                ]
            });

            if (existingOrder) {
                const message = existingOrder.orderStatus === "paid" ? `Jadwal ${pt.courtName} jam ${pt.startHour}:00 sudah tidak tersedia.` : `Jadwal ${pt.courtName} jam ${pt.startHour}:00 sedang dalam proses booking oleh orang lain.`;
                return res.status(409).json({ message });
            }
        }

        let serverTotal = 0;
        const validatedPlaytimes = [];
        const item_details = [];
        const bookingDate = format(new Date(playtimes[0].date), "yyyy-MM-dd");

        for (const pt of playtimes) {
            const price = await calculatePrice(pt);
            serverTotal += price;
            validatedPlaytimes.push({
                courtId: new ObjectId(pt.courtId), // Simpan sebagai ObjectId
                courtName: pt.courtName,
                date: new Date(pt.date),
                startHour: pt.startHour,
                price: price,
            });
            const playtimeId = `${pt.courtId}-${bookingDate}-${pt.startHour}`;
            item_details.push({
                id: playtimeId,
                price: price,
                quantity: 1,
                name: `Booking Lap. ${pt.courtName} jam ${pt.startHour}:00`,
            });
        }

        const orderId = `BINTON-${new ObjectId()}`;
        const newOrder = {
            _id: orderId,
            userId,
            playtimes: validatedPlaytimes,
            total: serverTotal,
            orderStatus: "pending",
            createdAt: new Date(),
            transactionToken: null,
        };
        await db.collection("orders").insertOne(newOrder);
        
        const parameter = {
            transaction_details: { order_id: orderId, gross_amount: serverTotal },
            customer_details: { email: userEmail },
            item_details: item_details,
            expiry: { unit: "minute", duration: 10 },
        };
        const transaction = await snap.createTransaction(parameter);
        const transactionToken = transaction.token;
        await db.collection("orders").updateOne({ _id: orderId }, { $set: { transactionToken: transactionToken } });

        const updatedSlots = playtimes.map((pt) => ({
            slotId: `${pt.courtId}-${bookingDate}-${pt.startHour}`,
            newStatus: 2, // pending
        }));

        req.app.get("socketio").emit("schedule_updated", { date: bookingDate, slots: updatedSlots });
        console.log(`📢 Memancarkan 'schedule_updated' (pending) untuk tanggal: ${bookingDate}`);

        res.status(201).json({ message: "Transaksi berhasil dibuat. Selesaikan pembayaran dalam 10 menit.", transactionToken, orderId: orderId });
    } catch (error) {
        console.error("Booking Error:", error);
        res.status(500).json({ message: "Gagal memproses booking." });
    }
});

// Endpoint lain (/api/payment-notification, /my-orders, dll) tidak banyak berubah
// Namun, pada `schedule_updated` emit, slotId sekarang harus menyertakan courtId.
app.post("/api/payment-notification", async (req, res) => {
  const notificationJson = req.body;
  try {
    const statusResponse = await snap.transaction.notification(notificationJson);
    const orderId = statusResponse.order_id;
    const transactionStatus = statusResponse.transaction_status;
    const fraudStatus = statusResponse.fraud_status;
    const order = await db.collection("orders").findOne({ _id: orderId });

    if (!order || order.orderStatus === "paid" || order.orderStatus === "failed") {
      return res.status(200).send("Notification ignored: Order not found or already processed.");
    }

    let newStatus = order.orderStatus;
    let isSuccess = false;

    if ((transactionStatus == "capture" && fraudStatus == "accept") || transactionStatus == "settlement") {
      newStatus = "paid";
      isSuccess = true;
    } else if (["cancel", "deny", "expire"].includes(transactionStatus)) {
      newStatus = "failed";
    }

    if (newStatus !== order.orderStatus) {
      await db.collection("orders").updateOne({ _id: orderId }, { $set: { orderStatus: newStatus, paymentResponse: statusResponse } });

      if (order.playtimes && order.playtimes.length > 0) {
        const bookingDate = format(new Date(order.playtimes[0].date), "yyyy-MM-dd");
        const updatedSlots = order.playtimes.map((pt) => {
          const ptDate = format(new Date(pt.date), "yyyy-MM-dd");
          return {
            slotId: `${pt.courtId}-${ptDate}-${pt.startHour}`, // Menggunakan courtId
            newStatus: isSuccess ? 0 : 1,
          };
        });

        req.app.get("socketio").emit("schedule_updated", { date: bookingDate, slots: updatedSlots });
        console.log(`📢 Memancarkan 'schedule_updated' (notif) untuk tanggal: ${bookingDate} dengan status: ${newStatus}`);
      }
    }
    res.status(200).send("Notification received successfully.");
  } catch (error) {
    console.error("Notification Error:", error);
    res.status(500).send("Internal Server Error");
  }
});
// ... sisa endpoint klien tetap sama

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

app.delete("/api/orders/:orderId", authUserMiddleware, async (req, res) => {
  try {
    const { orderId } = req.params;
    const userId = new ObjectId(req.user.userId);
    const order = await db.collection("orders").findOne({ _id: orderId });
    if (!order) {
      return res.status(404).json({ message: "Pesanan tidak ditemukan." });
    }
    if (!order.userId.equals(userId)) {
      return res.status(403).json({ message: "Anda tidak berhak menghapus pesanan ini." });
    }
    const threeDaysAgo = new Date();
    threeDaysAgo.setDate(threeDaysAgo.getDate() - 3);
    if (new Date(order.createdAt) > threeDaysAgo) {
      return res.status(400).json({ message: "Pesanan yang baru (kurang dari 3 hari) tidak dapat dihapus." });
    }
    await db.collection("orders").deleteOne({ _id: orderId });
    res.status(200).json({ message: "Riwayat pesanan berhasil dihapus." });
  } catch (error) {
    console.error("Delete Order Error:", error);
    res.status(500).json({ message: "Gagal menghapus pesanan." });
  }
});

app.put("/api/profile", authUserMiddleware, async (req, res) => {
  try {
    const userId = new ObjectId(req.user.userId);
    const { name, phone } = req.body;
    if (!name || !phone) return res.status(400).json({ message: "Nama dan nomor telepon tidak boleh kosong." });
    await db.collection("users").updateOne({ _id: userId }, { $set: { name: name, phone: phone } });
    const updatedUser = await db.collection("users").findOne({ _id: userId }, { projection: { password: 0 } });
    updatedUser.id = updatedUser._id;
    delete updatedUser._id;
    res.status(200).json({ message: "Profil berhasil diperbarui.", user: updatedUser });
  } catch (error) {
    res.status(500).json({ message: "Gagal memperbarui profil." });
  }
});


// === [DIROMBAK] ENDPOINTS UNTUK APLIKASI ADMIN ===

// --- [BARU] CRUD untuk Courts ---
app.get("/api/admin/courts", authAdminMiddleware, async (req, res) => {
  try {
    const courts = await db.collection("courts").find().sort({name: 1}).toArray();
    res.json(courts);
  } catch (error) {
    res.status(500).json({ message: "Gagal mengambil data lapangan." });
  }
});

app.post("/api/admin/courts", authAdminMiddleware, async (req, res) => {
    try {
        const { name, description } = req.body;
        if (!name) return res.status(400).json({ message: "Nama lapangan wajib diisi." });

        const newCourtData = { name, description, createdAt: new Date() };
        const result = await db.collection("courts").insertOne(newCourtData);
        const newCourtId = result.insertedId;

        // Saat lapangan baru dibuat, generate juga pengaturan default 7 hari untuknya
        const days = ["Minggu", "Senin", "Selasa", "Rabu", "Kamis", "Jumat", "Sabtu"];
        let settingsToInsert = [];
        for (let i = 0; i < 7; i++) {
            settingsToInsert.push({
                courtId: newCourtId,
                dayOfWeek: i,
                dayName: days[i],
                isActive: true,
                openingHour: 8,
                closingHour: 23,
                basePrice: 25000, // Harga default awal
                priceOverrides: [],
            });
        }
        await db.collection("settings").insertMany(settingsToInsert);
        
        res.status(201).json({ message: "Lapangan dan jadwal default berhasil dibuat.", newCourt: {...newCourtData, _id: newCourtId} });
    } catch (error) {
        res.status(500).json({ message: "Gagal membuat lapangan." });
    }
});

app.put("/api/admin/courts/:id", authAdminMiddleware, async (req, res) => {
    try {
        const { id } = req.params;
        const { name, description } = req.body;
        if (!name) return res.status(400).json({ message: "Nama lapangan wajib diisi." });

        await db.collection("courts").updateOne(
            { _id: new ObjectId(id) },
            { $set: { name, description } }
        );
        res.json({ message: "Data lapangan berhasil diperbarui." });
    } catch (error) {
        res.status(500).json({ message: "Gagal memperbarui lapangan." });
    }
});

app.delete("/api/admin/courts/:id", authAdminMiddleware, async (req, res) => {
    try {
        const { id } = req.params;
        const courtId = new ObjectId(id);

        // Hapus lapangan dan juga semua jadwal terkait
        await db.collection("courts").deleteOne({ _id: courtId });
        await db.collection("settings").deleteMany({ courtId: courtId });
        
        // Opsional: Handle member yang terdaftar di lapangan ini
        // Untuk saat ini kita biarkan, tapi di aplikasi production perlu ditangani

        res.json({ message: "Lapangan dan jadwal terkait berhasil dihapus." });
    } catch (error) {
        res.status(500).json({ message: "Gagal menghapus lapangan." });
    }
});


// --- Pengaturan Jadwal (Settings) disesuaikan ---
app.get("/api/admin/settings/:courtId", authAdminMiddleware, async (req, res) => {
  try {
    const { courtId } = req.params;
    const settings = await db.collection("settings")
      .find({ courtId: new ObjectId(courtId) })
      .sort({ dayOfWeek: 1 })
      .toArray();
    res.json(settings);
  } catch (error) {
    res.status(500).json({ message: "Error mengambil pengaturan." });
  }
});

app.put("/api/admin/settings", authAdminMiddleware, async (req, res) => {
  try {
    const updatedSettings = req.body; // Ini adalah array 7 jadwal untuk 1 lapangan
    for (const setting of updatedSettings) {
      const { _id, ...dataToUpdate } = setting;
      // Hapus courtId dari data yang diupdate agar tidak menimpa
      delete dataToUpdate.courtId; 
      await db.collection("settings").updateOne(
          { _id: new ObjectId(_id) },
          { $set: dataToUpdate }
        );
    }
    res.json({ message: "Pengaturan berhasil diperbarui." });
  } catch (error) {
    res.status(500).json({ message: "Gagal memperbarui pengaturan." });
  }
});


// --- Endpoint lain disesuaikan untuk menyertakan `courtId` ---
app.get("/api/admin/memberships", authAdminMiddleware, async (req, res) => {
  try {
    const members = await db.collection("memberships").find().toArray();
    res.json(members);
  } catch (error) {
    res.status(500).json({ message: "Error server." });
  }
});

app.post("/api/admin/memberships", authAdminMiddleware, async (req, res) => {
  try {
    const { courtId, ...memberData } = req.body;
    await db.collection("memberships").insertOne({
        ...memberData,
        courtId: new ObjectId(courtId) // Simpan sebagai ObjectId
    });
    res.status(201).json({ message: "Member berhasil ditambahkan." });
  } catch (error) {
    res.status(500).json({ message: "Gagal menambah member." });
  }
});

app.put("/api/admin/memberships/:id", authAdminMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { courtId, ...dataToUpdate } = req.body;
    await db.collection("memberships").updateOne(
        { _id: new ObjectId(id) },
        { $set: { ...dataToUpdate, courtId: new ObjectId(courtId) } }
      );
    res.json({ message: "Jadwal member berhasil diperbarui." });
  } catch (error) {
    res.status(500).json({ message: "Gagal memperbarui jadwal member." });
  }
});


// --- Endpoint Events tidak berubah (bersifat global) ---
app.get("/api/admin/events", authAdminMiddleware, async (req, res) => {
  try {
    const events = await db.collection("events").find().toArray();
    res.json(events);
  } catch (error) {
    res.status(500).json({ message: "Error server." });
  }
});

app.post("/api/admin/events", authAdminMiddleware, async (req, res) => {
  try {
    const eventData = req.body;
    eventData.date = new Date(eventData.date + "T00:00:00.000Z");
    await db.collection("events").deleteOne({ date: eventData.date });
    await db.collection("events").insertOne(eventData);
    res.status(201).json({ message: "Event berhasil dibuat." });
  } catch (error) {
    res.status(500).json({ message: "Gagal membuat event." });
  }
});

app.get("/api/admin/orders", authAdminMiddleware, async (req, res) => {
  try {
    const orders = await db.collection("orders").aggregate([
      // Urutkan dari yang terbaru
      { $sort: { createdAt: -1 } },
      // Gabungkan dengan data user untuk mendapatkan nama pemesan
      {
        $lookup: {
          from: "users",
          localField: "userId",
          foreignField: "_id",
          as: "userDetails"
        }
      },
      // Rapikan data user yang digabung
      {
        $unwind: {
          path: "$userDetails",
          preserveNullAndEmptyArrays: true // Tampilkan order meski user sudah dihapus
        }
      }
    ]).toArray();
    
    res.json(orders);
  } catch (error) {
    console.error("Gagal mengambil semua order:", error);
    res.status(500).json({ message: "Gagal mengambil riwayat pesanan." });
  }
});
