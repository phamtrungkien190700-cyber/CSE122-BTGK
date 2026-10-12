const authForm = document.querySelector("[data-auth]");
const AUTH_API_URL = "http://127.0.0.1:3002/api";

if (authForm) {
  const message = authForm.querySelector("[data-form-message]");
  const submitButton = authForm.querySelector('button[type="submit"]');

  authForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    message.textContent = "";
    delete message.dataset.state;

    const formData = new FormData(authForm);
    const password = formData.get("password");

    if (authForm.dataset.auth === "register") {
      if (password !== formData.get("confirm-password")) {
        message.textContent = "Mật khẩu xác nhận không khớp.";
        return;
      }
      if (!/[A-Za-z]/.test(password) || !/\d/.test(password)) {
        message.textContent = "Mật khẩu phải gồm ít nhất một chữ cái và một chữ số.";
        return;
      }
      if (!formData.has("agreement")) {
        message.textContent = "Vui lòng đồng ý với điều khoản để tiếp tục.";
        return;
      }
    }

    submitButton.disabled = true;
    try {
      const response = await fetch(`${AUTH_API_URL}/${authForm.dataset.auth}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: formData.get("name"),
          identity: formData.get("identity"),
          password,
        }),
      });
      const responseText = await response.text();
      let result;
      try {
        result = responseText ? JSON.parse(responseText) : null;
      } catch {
        throw new Error("Máy chủ trả về dữ liệu không hợp lệ. Hãy kiểm tra API tại http://127.0.0.1:3002.");
      }
      if (!result || typeof result !== "object") {
        throw new Error(`API LegalPath không trả về JSON (HTTP ${response.status}). Hãy chạy node server.js tại cổng 3002.`);
      }
      if (!response.ok) {
        throw new Error(result.message || "Không thể xử lý yêu cầu.");
      }

      message.dataset.state = "success";
      message.textContent = authForm.dataset.auth === "register"
        ? "Đăng ký thành công. Bạn có thể đăng nhập."
        : `Đăng nhập thành công. Xin chào ${result.user.name}!`;
      authForm.reset();
    } catch (error) {
      message.textContent = error instanceof TypeError
        ? "Không kết nối được API tại cổng 3002. Hãy kiểm tra node server.js và tải lại trang."
        : error.message;
    } finally {
      submitButton.disabled = false;
    }
  });
}