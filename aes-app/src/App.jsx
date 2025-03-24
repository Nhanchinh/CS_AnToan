import { useState, useRef } from 'react';
import { encrypt, decrypt } from './aes.js';
import './App.css';

function App() {
  const [inputText, setInputText] = useState('');
  const [encryptedText, setEncryptedText] = useState('');
  const [decryptedText, setDecryptedText] = useState('');
  const [secretKey, setSecretKey] = useState('');
  const [encryptionTime, setEncryptionTime] = useState(null);
  const [decryptionTime, setDecryptionTime] = useState(null);
  const [activeTab, setActiveTab] = useState('text'); // 'text' or 'file'
  const [keyLength, setKeyLength] = useState(16); // Default: AES-128 (16 bytes)
  const fileInputRef = useRef(null);
  const [fileName, setFileName] = useState('');
  const [fileContent, setFileContent] = useState('');
  const [isProcessing, setIsProcessing] = useState(false);

  const handleEncrypt = () => {
    if (!secretKey) {
      alert('Vui lòng nhập khóa bí mật!');
      return;
    }

    if (secretKey.length !== keyLength) {
      alert(`Khóa bí mật phải có độ dài ${keyLength} ký tự cho AES-${keyLength * 8}!`);
      return;
    }

    setIsProcessing(true);
    const textToEncrypt = activeTab === 'text' ? inputText : fileContent;

    setTimeout(() => {
      try {
        const startTime = performance.now();
        const result = encrypt(textToEncrypt, secretKey);
        const endTime = performance.now();

        setEncryptedText(result);
        setEncryptionTime(endTime - startTime);
        setDecryptedText('');
        setDecryptionTime(null);
      } catch (error) {
        alert('Lỗi khi mã hóa: ' + error.message);
      } finally {
        setIsProcessing(false);
      }
    }, 100);
  };

  const handleDecrypt = () => {
    if (!secretKey) {
      alert('Vui lòng nhập khóa bí mật!');
      return;
    }

    if (secretKey.length !== keyLength) {
      alert(`Khóa bí mật phải có độ dài ${keyLength} ký tự cho AES-${keyLength * 8}!`);
      return;
    }

    if (!encryptedText) {
      alert('Không có dữ liệu mã hóa để giải mã!');
      return;
    }

    setIsProcessing(true);

    setTimeout(() => {
      try {
        const startTime = performance.now();
        const result = decrypt(encryptedText, secretKey);
        const endTime = performance.now();

        setDecryptedText(result);
        setDecryptionTime(endTime - startTime);
      } catch (error) {
        alert('Lỗi khi giải mã: ' + error.message);
      } finally {
        setIsProcessing(false);
      }
    }, 100);
  };

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    setFileName(file.name);
    const reader = new FileReader();

    reader.onload = (event) => {
      setFileContent(event.target.result);
    };

    reader.readAsText(file);
  };

  const handleDownload = (content, type) => {
    const element = document.createElement('a');
    const file = new Blob([content], { type: 'text/plain' });
    element.href = URL.createObjectURL(file);
    element.download =
      type === 'encrypted'
        ? fileName
          ? `${fileName}.encrypted`
          : 'encrypted.txt'
        : fileName
          ? `${fileName}.decrypted`
          : 'decrypted.txt';
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  const clearAll = () => {
    setInputText('');
    setEncryptedText('');
    setDecryptedText('');
    setEncryptionTime(null);
    setDecryptionTime(null);
    setFileContent('');
    setFileName('');
    setSecretKey('');
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  return (
    <div className="container">
      <h1>Mã hóa và Giải mã AES</h1>

      <div className="key-section">
        <label htmlFor="keyLength">Loại mã hóa:</label>
        <select
          id="keyLength"
          value={keyLength}
          onChange={(e) => {
            setKeyLength(Number(e.target.value));
            setSecretKey(''); // Reset khóa khi thay đổi độ dài
          }}
        >
          <option value={16}>AES-128 (16 ký tự)</option>
          <option value={24}>AES-192 (24 ký tự)</option>
          <option value={32}>AES-256 (32 ký tự)</option>
        </select>
      </div>

      <div className="key-section">
        <label htmlFor="secretKey">Khóa bí mật ({keyLength} ký tự):</label>
        <input
          type="text"
          id="secretKey"
          value={secretKey}
          onChange={(e) => setSecretKey(e.target.value)}
          maxLength={keyLength}
          placeholder={`Nhập khóa ${keyLength} ký tự`}
        />
        <small>
          Lưu ý: Khóa phải đúng {keyLength} ký tự cho AES-{keyLength * 8}
        </small>
      </div>

      <div className="tabs">
        <button
          className={activeTab === 'text' ? 'active' : ''}
          onClick={() => setActiveTab('text')}
        >
          Văn bản
        </button>
        <button
          className={activeTab === 'file' ? 'active' : ''}
          onClick={() => setActiveTab('file')}
        >
          Tệp tin
        </button>
      </div>

      {activeTab === 'text' ? (
        <div className="text-input-section">
          <label htmlFor="inputText">Văn bản đầu vào:</label>
          <textarea
            id="inputText"
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            placeholder="Nhập văn bản cần mã hóa"
            rows={5}
          />
        </div>
      ) : (
        <div className="file-input-section">
          <label htmlFor="fileInput">Chọn tệp tin:</label>
          <input
            type="file"
            id="fileInput"
            ref={fileInputRef}
            onChange={handleFileChange}
          />
          {fileName && (
            <div className="file-info">
              <p>Tệp đã chọn: {fileName}</p>
              <p>Kích thước nội dung: {fileContent.length} ký tự</p>
            </div>
          )}
        </div>
      )}

      <div className="button-group">
        <button
          onClick={handleEncrypt}
          disabled={isProcessing || (!inputText && !fileContent) || !secretKey}
        >
          {isProcessing ? 'Đang mã hóa...' : 'Mã hóa'}
        </button>
        <button
          onClick={handleDecrypt}
          disabled={isProcessing || !encryptedText || !secretKey}
        >
          {isProcessing ? 'Đang giải mã...' : 'Giải mã'}
        </button>
        <button onClick={clearAll} disabled={isProcessing}>
          Xóa tất cả
        </button>
      </div>

      {encryptionTime !== null && (
        <div className="time-info">
          <p>Thời gian mã hóa: {encryptionTime.toFixed(2)} ms</p>
        </div>
      )}

      {encryptedText && (
        <div className="result-section">
          <h3>Kết quả mã hóa (AES-{keyLength * 8}):</h3>
          <textarea value={encryptedText} readOnly rows={5} />
          <button onClick={() => handleDownload(encryptedText, 'encrypted')}>
            Tải xuống văn bản mã hóa
          </button>
        </div>
      )}

      {decryptionTime !== null && (
        <div className="time-info">
          <p>Thời gian giải mã: {decryptionTime.toFixed(2)} ms</p>
        </div>
      )}

      {decryptedText && (
        <div className="result-section">
          <h3>Kết quả giải mã (AES-{keyLength * 8}):</h3>
          <textarea value={decryptedText} readOnly rows={5} />
          <button onClick={() => handleDownload(decryptedText, 'decrypted')}>
            Tải xuống văn bản giải mã
          </button>
        </div>
      )}
    </div>
  );
}

export default App;