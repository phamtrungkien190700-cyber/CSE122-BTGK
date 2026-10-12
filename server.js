const { createServer } = require("node:http");
const { randomBytes, scrypt, timingSafeEqual } = require("node:crypto");
const { promisify } = require("node:util");
const fs = require("node:fs/promises");
const path = require("node:path");

const scryptAsync = promisify(scrypt);
const ROOT = __dirname;
const USER_STORE_URL = process.env.USER_STORE_URL || "http://127.0.0.1:3000/list-user";
const PORT = Number(process.env.PORT || 3002);
const MAX_BODY_SIZE = 16 * 1024;
const LOCAL_ORIGIN = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/;

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function sendJson(response, status, body) {
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  response.end(JSON.stringify(body));
}

async function readJson(request) {
  if (!request.headers["content-type"]?.includes("application/json")) {
    throw new HttpError(415, "Yêu cầu phải có Content-Type application/json.");
  }

  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > MAX_BODY_SIZE) {
      throw new HttpError(413, "Dữ liệu gửi lên quá lớn.");
    }
    chunks.push(chunk);
  }

  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new HttpError(400, "Dữ liệu JSON không hợp lệ.");
  }
}

async function readUsers() {
  let response;
  try {
    response = await fetch(USER_STORE_URL);
  } catch (error) {
    console.error("Không kết nối được JSON Server:", error);
    throw new HttpError(502, "Không kết nối được JSON Server tại cổng 3000.");
  }

  if (!response.ok) {
    throw new HttpError(502, `JSON Server trả về lỗi HTTP ${response.status}.`);
  }
  let users;
  try {
    users = await response.json();
  } catch {
    throw new HttpError(502, "JSON Server trả về dữ liệu JSON không hợp lệ.");
  }
  if (!Array.isArray(users)) {
    throw new HttpError(502, "Route list-user phải trả về một mảng JSON.");
  }
  return users;
}

async function saveUser(user) {
  let response;
  try {
    response = await fetch(USER_STORE_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(user),
    });
  } catch (error) {
    console.error("Không thể ghi dữ liệu lên JSON Server:", error);
    throw new HttpError(502, "Không thể lưu tài khoản vào JSON Server.");
  }

  if (!response.ok) {
    throw new HttpError(502, `JSON Server không lưu được tài khoản (HTTP ${response.status}).`);
  }
}

let storeQueue = Promise.resolve();
function withUserStore(operation) {
  const result = storeQueue.then(operation, operation);
  storeQueue = result.then(() => undefined, () => undefined);
  return result;
}

function normalizeIdentity(identity) {
  return identity.trim().toLowerCase();
}

function validateCredentials(identity, password) {
  if (typeof identity !== "string" || !identity.trim()) {
    throw new HttpError(400, "Vui lòng nhập email hoặc số điện thoại.");
  }
  if (typeof password !== "string" || password.length < 8 || password.length > 128) {
    throw new HttpError(400, "Mật khẩu phải có từ 8 đến 128 ký tự.");
  }
  if (!/[A-Za-z]/.test(password) || !/\d/.test(password)) {
    throw new HttpError(400, "Mật khẩu phải gồm ít nhất một chữ cái và một chữ số.");
  }
}

async function hashPassword(password, salt) {
  return scryptAsync(password, salt, 64);
}

async function register(request, response) {
  const body = await readJson(request);
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new HttpError(400, "Dữ liệu gửi lên phải là một đối tượng JSON.");
  }
  const name = typeof body.name === "string" ? body.name.trim() : "";
  const identity = typeof body.identity === "string" ? normalizeIdentity(body.identity) : "";
  const { password } = body;

  if (!name || name.length > 100) {
    throw new HttpError(400, "Họ tên không được để trống và tối đa 100 ký tự.");
  }
  validateCredentials(identity, password);

  const user = await withUserStore(async () => {
    const users = await readUsers();
    if (users.some((item) => item.identity === identity)) {
      throw new HttpError(409, "Email hoặc số điện thoại này đã được đăng ký.");
    }

    const salt = randomBytes(16).toString("hex");
    const passwordHash = (await hashPassword(password, salt)).toString("hex");
    const newUser = {
      id: randomBytes(16).toString("hex"),
      name,
      identity,
      salt,
      passwordHash,
      createdAt: new Date().toISOString(),
    };

    await saveUser(newUser);
    return { name: newUser.name, identity: newUser.identity };
  });

  sendJson(response, 201, { message: "Đăng ký thành công.", user });
}

async function login(request, response) {
  const body = await readJson(request);
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new HttpError(400, "Dữ liệu gửi lên phải là một đối tượng JSON.");
  }
  const identity = typeof body.identity === "string" ? normalizeIdentity(body.identity) : "";
  const { password } = body;
  if (!identity || typeof password !== "string" || !password) {
    throw new HttpError(400, "Vui lòng nhập email/số điện thoại và mật khẩu.");
  }

  const user = await withUserStore(async () => {
    const users = await readUsers();
    const account = users.find((item) => item.identity === identity);
    if (!account || typeof account.salt !== "string" || typeof account.passwordHash !== "string") {
      return null;
    }

    const storedHash = Buffer.from(account.passwordHash, "hex");
    if (storedHash.length !== 64) return null;
    const submittedHash = await hashPassword(password, account.salt);
    if (!timingSafeEqual(storedHash, submittedHash)) return null;
    return { name: account.name, identity: account.identity };
  });

  if (!user) {
    throw new HttpError(401, "Email/số điện thoại hoặc mật khẩu không đúng.");
  }
  sendJson(response, 200, { message: "Đăng nhập thành công.", user });
}

async function serveStatic(request, response, pathname) {
  if (request.method !== "GET" && request.method !== "HEAD") {
    throw new HttpError(405, "Phương thức không được hỗ trợ.");
  }

  let decodedPath;
  try {
    decodedPath = decodeURIComponent(pathname);
  } catch {
    throw new HttpError(400, "Đường dẫn không hợp lệ.");
  }

  const relativePath = decodedPath === "/" ? "login.html" : decodedPath.slice(1);
  const filePath = path.resolve(ROOT, relativePath);
  const relativeToRoot = path.relative(ROOT, filePath);
  const normalizedRelativePath = relativeToRoot
    .replace(/\\/g, "/")
    .toLowerCase()
    .replace(/[. ]+(?=\/|$)/g, "");
  if (
    relativeToRoot.startsWith(`..${path.sep}`) ||
    relativeToRoot === ".." ||
    path.isAbsolute(relativeToRoot) ||
    normalizedRelativePath === "server.js" ||
    normalizedRelativePath === "data-user" ||
    normalizedRelativePath.startsWith("data-user/") ||
    path.extname(normalizedRelativePath) === ".json"
  ) {
    throw new HttpError(404, "Không tìm thấy trang.");
  }

  let contents;
  try {
    contents = await fs.readFile(filePath);
  } catch (error) {
    if (error.code === "ENOENT" || error.code === "EISDIR") {
      throw new HttpError(404, "Không tìm thấy trang.");
    }
    throw error;
  }

  const extension = path.extname(filePath);
  const contentTypes = {
    ".css": "text/css; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
  };
  response.writeHead(200, {
    "Content-Type": contentTypes[extension] || "application/octet-stream",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  });
  response.end(request.method === "HEAD" ? undefined : contents);
}

const server = createServer(async (request, response) => {
  const origin = request.headers.origin;
  if (origin && LOCAL_ORIGIN.test(origin)) {
    response.setHeader("Access-Control-Allow-Origin", origin);
    response.setHeader("Vary", "Origin");
    response.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    response.setHeader("Access-Control-Allow-Headers", "Content-Type");
  }

  if (request.method === "OPTIONS" && new URL(request.url, "http://localhost").pathname.startsWith("/api/")) {
    response.writeHead(204);
    response.end();
    return;
  }

  try {
    const url = new URL(request.url, "http://localhost");
    if (url.pathname === "/api/register" && request.method === "POST") {
      await register(request, response);
      return;
    }
    if (url.pathname === "/api/login" && request.method === "POST") {
      await login(request, response);
      return;
    }
    if (url.pathname.startsWith("/api/")) {
      throw new HttpError(404, "Không tìm thấy API.");
    }
    await serveStatic(request, response, url.pathname);
  } catch (error) {
    if (response.headersSent) {
      response.destroy(error);
      return;
    }
    if (error instanceof HttpError) {
      sendJson(response, error.status, { message: error.message });
      return;
    }
    console.error("Lỗi xử lý yêu cầu:", error);
    sendJson(response, 500, { message: "Có lỗi máy chủ. Vui lòng thử lại sau." });
  }
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`LegalPath đang chạy tại http://127.0.0.1:${PORT}`);
});
