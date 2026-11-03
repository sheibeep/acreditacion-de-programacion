
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'sheila_corporation_alliance_secret_2026';

// ---------- MIDDLEWARES ----------
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// ---------- PÁGINA PRINCIPAL ----------
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'prueba.html'));
});

// ---------- CONEXIÓN A MYSQL ----------
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: 'acreditacion',
    port: process.env.DB_PORT || 3306,
    waitForConnections: true,
    connectionLimit: 10,
    charset: 'utf8mb4'
});

// Comprobar conexión
(async () => {
    try {
        const conn = await pool.getConnection();
        console.log('✅ Conexión con MySQL exitosa (base: acreditacion)');
        conn.release();
    } catch (err) {
        console.error('❌ Error de conexión con MySQL:', err.message);
    }
})();

// ---------- AUTENTICACIÓN ----------
function verificarToken(req, res, next) {
    const header = req.headers['authorization'];

    if (!header) {
        return res.status(401).json({ mensaje: 'Token requerido' });
    }

    const token = header.split(' ')[1];

    try {
        req.usuario = jwt.verify(token, JWT_SECRET);
        next();
    } catch {
        return res.status(403).json({
            mensaje: 'Token inválido o expirado'
        });
    }
}

// ======================================================
// REGISTRO
// ======================================================
app.post('/api/registro', async (req, res) => {
    const { usuario, contraseña } = req.body;

    if (!usuario || !contraseña) {
        return res.status(400).json({
            mensaje: 'Usuario y contraseña son obligatorios'
        });
    }

    if (usuario.length > 11) {
        return res.status(400).json({
            mensaje: 'El usuario no puede superar los 11 caracteres'
        });
    }

    if (contraseña.length < 4) {
        return res.status(400).json({
            mensaje: 'La contraseña debe tener al menos 4 caracteres'
        });
    }

    try {
        const [existe] = await pool.query(
            'SELECT id_usuario FROM usuarios WHERE usuario = ?',
            [usuario]
        );

        if (existe.length > 0) {
            return res.status(400).json({
                mensaje: 'El usuario ya existe'
            });
        }

        const hash = await bcrypt.hash(contraseña, 10);

        await pool.query(
            'INSERT INTO usuarios (usuario, contraseña) VALUES (?, ?)',
            [usuario, hash]
        );

        res.json({
            mensaje: 'Usuario creado correctamente'
        });

    } catch (err) {
        console.error('Error registro:', err.message);

        res.status(500).json({
            mensaje: 'Error al registrar el usuario'
        });
    }
});

// ======================================================
// LOGIN
// ======================================================
app.post('/api/login', async (req, res) => {
    const { usuario, contraseña } = req.body;

    if (!usuario || !contraseña) {
        return res.status(400).json({
            mensaje: 'Usuario y contraseña son obligatorios'
        });
    }

    try {
        const [rows] = await pool.query(
            `SELECT id_usuario, usuario, contraseña
             FROM usuarios
             WHERE usuario = ?
             LIMIT 1`,
            [usuario]
        );

        if (rows.length === 0) {
            return res.status(401).json({
                mensaje: 'Usuario o contraseña incorrectos'
            });
        }

        const user = rows[0];

        const passwordValida = await bcrypt.compare(
            contraseña,
            user.contraseña
        );

        if (!passwordValida) {
            return res.status(401).json({
                mensaje: 'Usuario o contraseña incorrectos'
            });
        }

        const token = jwt.sign(
            {
                id: user.id_usuario,
                usuario: user.usuario
            },
            JWT_SECRET,
            { expiresIn: '2h' }
        );

        res.json({
            mensaje: 'Login exitoso',
            token,
            usuario: {
                id: user.id_usuario,
                nombre: user.usuario
            }
        });

    } catch (err) {
        console.error('Error login:', err.message);

        res.status(500).json({
            mensaje: 'Error del servidor'
        });
    }
});

// ======================================================
// CONTACTO Y CONSULTAS
// ======================================================
app.post('/api/contacto', async (req, res) => {
    const { nombre, correo, telefono, motivo, urgencia } = req.body;

    if (!nombre || !correo) {
        return res.status(400).json({
            mensaje: 'Nombre y correo son obligatorios'
        });
    }

    let conn;

    try {
        conn = await pool.getConnection();

        await conn.beginTransaction();

        // Generar identificador del cliente
        const idCliente = 'CLI' + Date.now();

        // Guardar datos del cliente
        await conn.query(
            `INSERT INTO contacto
            (Id_cliente, nombre_apellido, correo, telefono)
            VALUES (?, ?, ?, ?)`,
            [
                idCliente,
                nombre,
                correo,
                telefono || ''
            ]
        );

        // Guardar consulta
        if (motivo || urgencia) {
            await conn.query(
                `INSERT INTO consultas
                (motivos, urgencia, Id_cliente)
                VALUES (?, ?, ?)`,
                [
                    motivo || 'Consulta general',
                    urgencia || 'Normal',
                    idCliente
                ]
            );
        }

        await conn.commit();

        console.log('✅ Contacto registrado:', idCliente);

        res.json({
            mensaje: 'Consulta registrada correctamente',
            id_cliente: idCliente
        });

    } catch (err) {

        if (conn) {
            await conn.rollback();
        }

        console.error('❌ Error contacto:', err);

        res.status(500).json({
            mensaje: 'Error al guardar la consulta'
        });

    } finally {
        if (conn) {
            conn.release();
        }
    }
});

// ---------- ARRANCAR SERVIDOR ----------
app.listen(PORT, () => {
    console.log(
        `🚀 Sheila Corporation Alliance — Servidor en http://localhost:${PORT}`
    );
});