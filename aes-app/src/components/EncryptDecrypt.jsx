import { useState, useEffect } from "react";
import { AES } from "../utils/aes";
import { saveAs } from "file-saver";

const EncryptDecrypt = ({ fileContent }) => {
    const [key, setKey] = useState("");
    const [encryptedData, setEncryptedData] = useState("");
    const [decryptedData, setDecryptedData] = useState("");
    const [encryptionTime, setEncryptionTime] = useState(null);
    const [decryptionTime, setDecryptionTime] = useState(null);
    const [isReady, setIsReady] = useState(false);

    // Khi fileContent hoặc key thay đổi, cập nhật trạng thái sẵn sàng
    useEffect(() => {
        setIsReady(!!fileContent && !!key);
    }, [fileContent, key]);

    const handleEncrypt = () => {
        if (!isReady) {
            alert("Vui lòng nhập khóa và tải file!");
            return;
        }

        const startTime = performance.now();
        const encrypted = AES.encrypt(fileContent, key);
        const endTime = performance.now();

        setEncryptedData(encrypted);
        setEncryptionTime(endTime - startTime);
    };

    const handleDecrypt = () => {
        if (!encryptedData || !isReady) {
            alert("Vui lòng nhập khóa và mã hóa file trước!");
            return;
        }

        const startTime = performance.now();
        const decrypted = AES.decrypt(encryptedData, key);
        const endTime = performance.now();

        setDecryptedData(decrypted);
        setDecryptionTime(endTime - startTime);
    };

    const handleDownload = (data, filename) => {
        const blob = new Blob([data], { type: "text/plain;charset=utf-8" });
        saveAs(blob, filename);
    };

    return (
        <div>
            <input
                type="text"
                placeholder="Nhập khóa AES"
                value={key}
                onChange={(e) => setKey(e.target.value)}
            />

            <button onClick={handleEncrypt} disabled={!isReady}>
                Mã hóa
            </button>
            {encryptionTime && <p>Thời gian mã hóa: {encryptionTime} ms</p>}

            <button onClick={handleDecrypt} disabled={!encryptedData || !isReady}>
                Giải mã
            </button>
            {decryptionTime && <p>Thời gian giải mã: {decryptionTime} ms</p>}

            {encryptedData && (
                <div>
                    <h3>Dữ liệu mã hóa:</h3>
                    <p>{encryptedData}</p>
                    <button onClick={() => handleDownload(encryptedData, "encrypted.txt")}>
                        Tải file mã hóa
                    </button>
                </div>
            )}

            {decryptedData && (
                <div>
                    <h3>Dữ liệu giải mã:</h3>
                    <p>{decryptedData}</p>
                    <button onClick={() => handleDownload(decryptedData, "decrypted.txt")}>
                        Tải file giải mã
                    </button>
                </div>
            )}
        </div>
    );
};

export default EncryptDecrypt;
