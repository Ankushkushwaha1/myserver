const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const session = require("express-session");

const app = express();

const PORT = Number(process.env.PORT) || 3000;
const HOST = "0.0.0.0";

const ROOT_DIR = path.resolve(__dirname);
const MEDIA_DIR = path.join(ROOT_DIR, "media");
const DATA_DIR = path.join(ROOT_DIR, "data");
const CONFIG_FILE = path.join(DATA_DIR, "config.json");

fs.mkdirSync(MEDIA_DIR, { recursive: true });
fs.mkdirSync(DATA_DIR, { recursive: true });

function loadConfig() {
    try {
        if (!fs.existsSync(CONFIG_FILE)) {
            return null;
        }

        return JSON.parse(
            fs.readFileSync(CONFIG_FILE, "utf8")
        );
    } catch (error) {
        console.error("Could not read configuration.");
        process.exit(1);
    }
}

let config = loadConfig();

function saveConfig(data) {
    const temporaryFile = CONFIG_FILE + ".tmp";

    fs.writeFileSync(
        temporaryFile,
        JSON.stringify(data, null, 2),
        {
            encoding: "utf8",
            mode: 0o600
        }
    );

    fs.renameSync(
        temporaryFile,
        CONFIG_FILE
    );
}

/*
|--------------------------------------------------------------------------
| Security
|--------------------------------------------------------------------------
*/

app.disable("x-powered-by");

app.use(
    helmet({
        contentSecurityPolicy: false
    })
);

app.use(
    rateLimit({
        windowMs: 15 * 60 * 1000,
        limit: 300,
        standardHeaders: true,
        legacyHeaders: false
    })
);

app.use(
    express.json({
        limit: "1mb"
    })
);

/*
|--------------------------------------------------------------------------
| Session
|--------------------------------------------------------------------------
*/

const sessionSecret =
    config?.sessionSecret ||
    crypto.randomBytes(64).toString("hex");

if (!config) {
    config = {
        sessionSecret
    };
}

app.use(
    session({
        name: "myserver_session",
        secret: sessionSecret,
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            sameSite: "strict",
            secure: false,
            maxAge: 1000 * 60 * 60 * 12
        }
    })
);

/*
|--------------------------------------------------------------------------
| Authentication helpers
|--------------------------------------------------------------------------
*/

function isAuthenticated(req) {
    return Boolean(
        req.session &&
        req.session.authenticated === true
    );
}

function requireAuth(req, res, next) {
    if (isAuthenticated(req)) {
        return next();
    }

    return res.status(401).json({
        error: "Authentication required"
    });
}

/*
|--------------------------------------------------------------------------
| Filename safety
|--------------------------------------------------------------------------
*/

function sanitizeFilename(filename) {
    let name = path.basename(
        String(filename || "")
    );

    name = name.replace(
        /[\x00-\x1F\x80-\x9F]/g,
        ""
    );

    name = name.replace(
        /[<>:"/\\|?*]/g,
        "_"
    );

    name = name.trim();

    if (
        !name ||
        name === "." ||
        name === ".."
    ) {
        name = "file";
    }

    return name;
}

/*
|--------------------------------------------------------------------------
| Safe file path
|--------------------------------------------------------------------------
*/

function safeFilePath(filename) {
    const cleanName =
        sanitizeFilename(filename);

    const filePath =
        path.resolve(
            MEDIA_DIR,
            cleanName
        );

    const mediaRoot =
        MEDIA_DIR.endsWith(path.sep)
            ? MEDIA_DIR
            : MEDIA_DIR + path.sep;

    if (
        filePath !== MEDIA_DIR &&
        !filePath.startsWith(mediaRoot)
    ) {
        return null;
    }

    return filePath;
}

/*
|--------------------------------------------------------------------------
| Multer
|--------------------------------------------------------------------------
|
| There is deliberately NO application file-size limit.
|
| The practical limits are:
| - available disk space
| - operating system/filesystem limits
| - browser/network limitations
|
*/

const storage = multer.diskStorage({

    destination: (req, file, callback) => {
        callback(null, MEDIA_DIR);
    },

    filename: (req, file, callback) => {

        const originalName =
            sanitizeFilename(
                file.originalname
            );

        const randomId =
            crypto
                .randomBytes(16)
                .toString("hex");

        callback(
            null,
            `${randomId}-${originalName}`
        );
    }
});

const upload = multer({
    storage,

    limits: {
        files: 100
    }
});

/*
|--------------------------------------------------------------------------
| First-run setup
|--------------------------------------------------------------------------
*/

app.get("/api/setup-status", (req, res) => {

    res.json({
        setupRequired:
            !config.username ||
            !config.passwordHash
    });
});

app.post("/api/setup", async (req, res) => {

    if (
        config.username &&
        config.passwordHash
    ) {
        return res.status(409).json({
            error:
                "Administrator account already exists."
        });
    }

    const {
        username,
        password,
        confirmPassword
    } = req.body || {};

    if (
        typeof username !== "string" ||
        typeof password !== "string" ||
        typeof confirmPassword !== "string"
    ) {
        return res.status(400).json({
            error: "Invalid setup data."
        });
    }

    const cleanUsername =
        username.trim();

    if (
        cleanUsername.length < 3 ||
        cleanUsername.length > 64
    ) {
        return res.status(400).json({
            error:
                "Username must be 3-64 characters."
        });
    }

    if (
        !/^[a-zA-Z0-9._-]+$/.test(
            cleanUsername
        )
    ) {
        return res.status(400).json({
            error:
                "Username contains invalid characters."
        });
    }

    if (password.length < 12) {
        return res.status(400).json({
            error:
                "Password must be at least 12 characters."
        });
    }

    if (password !== confirmPassword) {
        return res.status(400).json({
            error:
                "Passwords do not match."
        });
    }

    const passwordHash =
        await bcrypt.hash(
            password,
            12
        );

    config = {
        username: cleanUsername,
        passwordHash,
        sessionSecret:
            config.sessionSecret ||
            crypto.randomBytes(64).toString("hex")
    };

    saveConfig(config);

    res.json({
        success: true
    });
});

/*
|--------------------------------------------------------------------------
| Login
|--------------------------------------------------------------------------
*/

app.post("/api/login", async (req, res) => {

    if (
        !config.username ||
        !config.passwordHash
    ) {
        return res.status(428).json({
            error:
                "Administrator setup is required."
        });
    }

    const {
        username,
        password
    } = req.body || {};

    if (
        typeof username !== "string" ||
        typeof password !== "string"
    ) {
        return res.status(400).json({
            error: "Invalid credentials."
        });
    }

    const usernameMatches =
        crypto.timingSafeEqual(
            Buffer.from(username),
            Buffer.from(config.username)
        );

    const passwordMatches =
        await bcrypt.compare(
            password,
            config.passwordHash
        );

    if (
        !usernameMatches ||
        !passwordMatches
    ) {
        return res.status(401).json({
            error:
                "Invalid username or password."
        });
    }

    req.session.regenerate(error => {

        if (error) {
            return res.status(500).json({
                error:
                    "Could not create session."
            });
        }

        req.session.authenticated = true;

        res.json({
            success: true
        });
    });
});

/*
|--------------------------------------------------------------------------
| Current authentication status
|--------------------------------------------------------------------------
*/

app.get("/api/me", (req, res) => {

    res.json({
        authenticated:
            isAuthenticated(req),

        username:
            isAuthenticated(req)
                ? config.username
                : null
    });
});

/*
|--------------------------------------------------------------------------
| Logout
|--------------------------------------------------------------------------
*/

app.post(
    "/api/logout",
    requireAuth,
    (req, res) => {

        req.session.destroy(error => {

            if (error) {
                return res.status(500).json({
                    error:
                        "Could not log out."
                });
            }

            res.clearCookie(
                "myserver_session"
            );

            res.json({
                success: true
            });
        });
    }
);

/*
|--------------------------------------------------------------------------
| Upload
|--------------------------------------------------------------------------
*/

app.post(
    "/api/upload",
    requireAuth,
    upload.array("files", 100),
    (req, res) => {

        const uploaded =
            (req.files || []).map(file => ({
                name: file.filename,
                size: file.size
            }));

        res.json({
            success: true,
            files: uploaded
        });
    }
);

/*
|--------------------------------------------------------------------------
| List files
|--------------------------------------------------------------------------
*/

app.get(
    "/api/files",
    requireAuth,
    (req, res) => {

        const files =
            fs.readdirSync(MEDIA_DIR)
            .map(name => {

                const filePath =
                    path.join(
                        MEDIA_DIR,
                        name
                    );

                let stat;

                try {
                    stat =
                        fs.statSync(filePath);
                } catch {
                    return null;
                }

                if (!stat.isFile()) {
                    return null;
                }

                return {
                    name,
                    size: stat.size,
                    modified:
                        stat.mtimeMs
                };
            })
            .filter(Boolean);

        files.sort(
            (a, b) =>
                b.modified - a.modified
        );

        res.json(files);
    }
);

/*
|--------------------------------------------------------------------------
| File streaming / download
|--------------------------------------------------------------------------
*/

app.get(
    "/api/file/:filename",
    requireAuth,
    (req, res) => {

        const filePath =
            safeFilePath(
                req.params.filename
            );

        if (
            !filePath ||
            !fs.existsSync(filePath)
        ) {
            return res.status(404).send(
                "File not found."
            );
        }

        let stat;

        try {
            stat =
                fs.statSync(filePath);
        } catch {
            return res.status(404).send(
                "File not found."
            );
        }

        if (!stat.isFile()) {
            return res.status(400).send(
                "Not a file."
            );
        }

        const range =
            req.headers.range;

        /*
        | No range = normal download.
        */

        if (!range) {

            return res.sendFile(
                filePath,
                {
                    acceptRanges: true,
                    cacheControl: false
                }
            );
        }

        /*
        | HTTP Range Request
        | Allows large video files to
        | seek without downloading
        | everything first.
        */

        const match =
            range.match(
                /^bytes=(\d*)-(\d*)$/
            );

        if (!match) {
            return res.status(416).send(
                "Invalid range."
            );
        }

        let start;
        let end;

        if (match[1] === "") {

            const suffixLength =
                Number(match[2]);

            if (
                !Number.isSafeInteger(
                    suffixLength
                ) ||
                suffixLength <= 0
            ) {
                return res.status(416).send(
                    "Invalid range."
                );
            }

            start =
                Math.max(
                    stat.size - suffixLength,
                    0
                );

            end =
                stat.size - 1;

        } else {

            start =
                Number(match[1]);

            end =
                match[2] === ""
                    ? stat.size - 1
                    : Number(match[2]);
        }

        if (
            !Number.isSafeInteger(start) ||
            !Number.isSafeInteger(end) ||
            start < 0 ||
            end < start ||
            start >= stat.size
        ) {
            res.setHeader(
                "Content-Range",
                `bytes */${stat.size}`
            );

            return res.status(416).send(
                "Range Not Satisfiable."
            );
        }

        end =
            Math.min(
                end,
                stat.size - 1
            );

        const chunkSize =
            end - start + 1;

        res.status(206);

        res.setHeader(
            "Content-Range",
            `bytes ${start}-${end}/${stat.size}`
        );

        res.setHeader(
            "Accept-Ranges",
            "bytes"
        );

        res.setHeader(
            "Content-Length",
            chunkSize
        );

        fs.createReadStream(
            filePath,
            {
                start,
                end
            }
        ).pipe(res);
    }
);

/*
|--------------------------------------------------------------------------
| Delete
|--------------------------------------------------------------------------
*/

app.delete(
    "/api/file/:filename",
    requireAuth,
    (req, res) => {

        const filePath =
            safeFilePath(
                req.params.filename
            );

        if (
            !filePath ||
            !fs.existsSync(filePath)
        ) {
            return res.status(404).json({
                error:
                    "File not found."
            });
        }

        try {
            const stat =
                fs.statSync(filePath);

            if (!stat.isFile()) {
                return res.status(400).json({
                    error:
                        "Not a file."
                });
            }

            fs.unlinkSync(filePath);

            res.json({
                success: true
            });

        } catch {
            res.status(500).json({
                error:
                    "Could not delete file."
            });
        }
    }
);

/*
|--------------------------------------------------------------------------
| Web interface
|--------------------------------------------------------------------------
*/

app.get("/", (req, res) => {

    res.type("html").send(`<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport"
content="width=device-width,initial-scale=1">

<title>MyServer</title>

<style>

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    background: #0d0d0f;
    color: #fff;
    font-family:
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;
}

header {
    padding: 24px;
    border-bottom: 1px solid #29292d;
}

.container {
    max-width: 1200px;
    margin: auto;
    padding: 25px;
}

.card {
    background: #18181b;
    border: 1px solid #29292d;
    border-radius: 16px;
    padding: 24px;
    margin-bottom: 20px;
}

h1 {
    margin-top: 0;
}

input {
    width: 100%;
    max-width: 420px;
    padding: 13px;
    margin: 6px 0;
    border-radius: 9px;
    border: 1px solid #444;
    background: #101012;
    color: white;
}

button {
    padding: 11px 17px;
    margin: 6px 4px 6px 0;
    border: 0;
    border-radius: 9px;
    cursor: pointer;
}

.primary {
    background: white;
    color: black;
}

.danger {
    background: #b42318;
    color: white;
}

.drop {
    border: 2px dashed #444;
    border-radius: 14px;
    padding: 40px;
    text-align: center;
}

.grid {
    display: grid;
    grid-template-columns:
        repeat(
            auto-fill,
            minmax(250px, 1fr)
        );
    gap: 18px;
}

.file {
    background: #111113;
    border: 1px solid #29292d;
    border-radius: 13px;
    padding: 14px;
    overflow: hidden;
}

.preview {
    width: 100%;
    height: 220px;
    object-fit: contain;
    background: #050505;
    border-radius: 9px;
}

.filename {
    word-break: break-all;
    margin: 12px 0 5px;
}

.size {
    color: #999;
    font-size: 13px;
}

a {
    color: white;
}

.hidden {
    display: none;
}

.error {
    color: #ff7777;
}

.success {
    color: #70e000;
}

</style>
</head>

<body>

<header>
    <strong>MyServer</strong>
</header>

<div class="container">

<section id="setup" class="card hidden">

    <h1>First-time setup</h1>

    <p>
        Create the administrator account
        for this installation.
    </p>

    <input
        id="setupUsername"
        placeholder="Username"
        autocomplete="username"
    >

    <br>

    <input
        id="setupPassword"
        type="password"
        placeholder="Password — minimum 12 characters"
        autocomplete="new-password"
    >

    <br>

    <input
        id="setupConfirm"
        type="password"
        placeholder="Confirm password"
        autocomplete="new-password"
    >

    <br>

    <button
        class="primary"
        onclick="createAccount()"
    >
        Create administrator
    </button>

    <p id="setupMessage"></p>

</section>


<section id="login" class="card hidden">

    <h1>MyServer</h1>

    <p>Sign in to your local server.</p>

    <input
        id="loginUsername"
        placeholder="Username"
        autocomplete="username"
    >

    <br>

    <input
        id="loginPassword"
        type="password"
        placeholder="Password"
        autocomplete="current-password"
    >

    <br>

    <button
        class="primary"
        onclick="login()"
    >
        Login
    </button>

    <p id="loginMessage"></p>

</section>


<section id="app" class="hidden">

    <div class="card">

        <h1>MyServer</h1>

        <p>
            Store and share any type of file.
        </p>

        <div
            class="drop"
            id="drop"
        >

            <h2>
                Drop files here
            </h2>

            <p>
                or select files from your device
            </p>

            <input
                id="fileInput"
                type="file"
                multiple
            >

            <br>

            <button
                class="primary"
                onclick="uploadFiles()"
            >
                Upload
            </button>

            <p id="uploadStatus"></p>

        </div>

        <button onclick="logout()">
            Logout
        </button>

    </div>


    <div class="card">

        <h2>Your files</h2>

        <div
            id="fileGrid"
            class="grid"
        ></div>

    </div>

</section>

</div>


<script>

async function initialize() {

    const response =
        await fetch(
            "/api/setup-status"
        );

    const status =
        await response.json();

    if (status.setupRequired) {

        show("setup");

    } else {

        const me =
            await fetch("/api/me");

        const data =
            await me.json();

        if (data.authenticated) {

            show("app");
            loadFiles();

        } else {

            show("login");
        }
    }
}


function show(id) {

    [
        "setup",
        "login",
        "app"
    ].forEach(section => {

        document
            .getElementById(section)
            .classList.add("hidden");

    });

    document
        .getElementById(id)
        .classList.remove("hidden");
}


async function createAccount() {

    const username =
        document
            .getElementById(
                "setupUsername"
            ).value;

    const password =
        document
            .getElementById(
                "setupPassword"
            ).value;

    const confirmPassword =
        document
            .getElementById(
                "setupConfirm"
            ).value;

    const response =
        await fetch(
            "/api/setup",
            {
                method: "POST",
                headers: {
                    "Content-Type":
                        "application/json"
                },
                body: JSON.stringify({
                    username,
                    password,
                    confirmPassword
                })
            }
        );

    const data =
        await response.json();

    const message =
        document.getElementById(
            "setupMessage"
        );

    if (!response.ok) {

        message.className = "error";
        message.innerText =
            data.error ||
            "Setup failed.";

        return;
    }

    message.className = "success";
    message.innerText =
        "Account created.";

    setTimeout(
        () => show("login"),
        500
    );
}


async function login() {

    const username =
        document
            .getElementById(
                "loginUsername"
            ).value;

    const password =
        document
            .getElementById(
                "loginPassword"
            ).value;

    const response =
        await fetch(
            "/api/login",
            {
                method: "POST",
                headers: {
                    "Content-Type":
                        "application/json"
                },
                body: JSON.stringify({
                    username,
                    password
                })
            }
        );

    const data =
        await response.json();

    const message =
        document.getElementById(
            "loginMessage"
        );

    if (!response.ok) {

        message.className = "error";
        message.innerText =
            data.error ||
            "Login failed.";

        return;
    }

    show("app");

    loadFiles();
}


async function logout() {

    await fetch(
        "/api/logout",
        {
            method: "POST"
        }
    );

    location.reload();
}


async function uploadFiles() {

    const input =
        document.getElementById(
            "fileInput"
        );

    const status =
        document.getElementById(
            "uploadStatus"
        );

    if (!input.files.length) {
        return;
    }

    for (
        let i = 0;
        i < input.files.length;
        i++
    ) {

        const file =
            input.files[i];

        status.innerText =
            "Uploading " +
            (i + 1) +
            "/" +
            input.files.length +
            ": " +
            file.name;

        const form =
            new FormData();

        form.append(
            "files",
            file,
            file.name
        );

        const response =
            await fetch(
                "/api/upload",
                {
                    method: "POST",
                    body: form
                }
            );

        if (!response.ok) {

            const data =
                await response.json()
                .catch(() => ({}));

            status.className =
                "error";

            status.innerText =
                data.error ||
                "Upload failed.";

            return;
        }
    }

    status.className =
        "success";

    status.innerText =
        "Upload complete.";

    input.value = "";

    loadFiles();
}


function formatBytes(bytes) {

    if (bytes === 0) {
        return "0 B";
    }

    const units = [
        "B",
        "KB",
        "MB",
        "GB",
        "TB",
        "PB"
    ];

    const index =
        Math.floor(
            Math.log(bytes) /
            Math.log(1024)
        );

    return (
        bytes /
        Math.pow(1024, index)
    ).toFixed(2) +
        " " +
        units[index];
}


function isImage(name) {

    return [
        "jpg",
        "jpeg",
        "png",
        "gif",
        "webp",
        "avif",
        "bmp"
    ].includes(
        name
            .split(".")
            .pop()
            .toLowerCase()
    );
}


function isVideo(name) {

    return [
        "mp4",
        "mov",
        "m4v",
        "webm",
        "ogg"
    ].includes(
        name
            .split(".")
            .pop()
            .toLowerCase()
    );
}


async function loadFiles() {

    const response =
        await fetch(
            "/api/files"
        );

    if (!response.ok) {

        location.reload();

        return;
    }

    const files =
        await response.json();

    const grid =
        document.getElementById(
            "fileGrid"
        );

    grid.innerHTML = "";

    files.forEach(file => {

        const card =
            document.createElement(
                "div"
            );

        card.className = "file";

        if (isImage(file.name)) {

            const image =
                document.createElement(
                    "img"
                );

            image.className =
                "preview";

            image.src =
                "/api/file/" +
                encodeURIComponent(
                    file.name
                );

            image.loading =
                "lazy";

            card.appendChild(
                image
            );

        } else if (
            isVideo(file.name)
        ) {

            const video =
                document.createElement(
                    "video"
                );

            video.className =
                "preview";

            video.controls = true;

            video.preload =
                "metadata";

            video.src =
                "/api/file/" +
                encodeURIComponent(
                    file.name
                );

            card.appendChild(
                video
            );
        }

        const name =
            document.createElement(
                "div"
            );

        name.className =
            "filename";

        name.innerText =
            file.name;

        card.appendChild(
            name
        );

        const size =
            document.createElement(
                "div"
            );

        size.className =
            "size";

        size.innerText =
            formatBytes(file.size);

        card.appendChild(
            size
        );

        const download =
            document.createElement(
                "a"
            );

        download.href =
            "/api/file/" +
            encodeURIComponent(
                file.name
            );

        download.download =
            file.name;

        download.innerText =
            "Download";

        card.appendChild(
            document.createElement(
                "br"
            )
        );

        card.appendChild(
            download
        );

        const deleteButton =
            document.createElement(
                "button"
            );

        deleteButton.className =
            "danger";

        deleteButton.innerText =
            "Delete";

        deleteButton.onclick =
            () => deleteFile(
                file.name
            );

        card.appendChild(
            deleteButton
        );

        grid.appendChild(
            card
        );
    });
}


async function deleteFile(name) {

    if (
        !confirm(
            "Permanently delete this file?"
        )
    ) {
        return;
    }

    const response =
        await fetch(
            "/api/file/" +
            encodeURIComponent(name),
            {
                method: "DELETE"
            }
        );

    if (response.ok) {
        loadFiles();
    }
}


/*
|--------------------------------------------------------------------------
| Drag and drop
|--------------------------------------------------------------------------
*/

const drop =
    document.getElementById("drop");

drop.addEventListener(
    "dragover",
    event => {
        event.preventDefault();
    }
);

drop.addEventListener(
    "drop",
    event => {

        event.preventDefault();

        const input =
            document.getElementById(
                "fileInput"
            );

        input.files =
            event.dataTransfer.files;
    }
);

initialize();

</script>

</body>
</html>`);
});

/*
|--------------------------------------------------------------------------
| Error handling
|--------------------------------------------------------------------------
*/

app.use(
    (error, req, res, next) => {

        console.error(error);

        if (
            error instanceof
            multer.MulterError
        ) {

            return res.status(400).json({
                error: error.message
            });
        }

        res.status(500).json({
            error:
                "Internal server error."
        });
    }
);

/*
|--------------------------------------------------------------------------
| Start
|--------------------------------------------------------------------------
*/

app.listen(
    PORT,
    HOST,
    () => {

        console.log("");
        console.log(
            "======================================"
        );
        console.log(
            "              MYSERVER"
        );
        console.log(
            "======================================"
        );
        console.log("");
        console.log(
            `Local: http://localhost:${PORT}`
        );
        console.log("");
        console.log(
            "No application file-size limit."
        );
        console.log(
            "LAN access enabled."
        );
        console.log("");
        console.log(
            "Press Control + C to stop."
        );
        console.log("");
    }
);
