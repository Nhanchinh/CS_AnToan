import { useEffect, useState } from "react";

const FileUpload = ({ onFileLoad }) => {
    const [fileName, setFileName] = useState("");
    const [fileContent, setFileContent] = useState("");

    const handleFileChange = (event) => {
        const file = event.target.files[0];
        if (!file) return;

        setFileName(file.name);
        const reader = new FileReader();
        reader.onload = (e) => {
            setFileContent(e.target.result); // Lưu vào state trước
        };
        reader.readAsText(file);
    };

    // Đợi fileContent cập nhật xong rồi mới gửi lên component cha
    useEffect(() => {
        if (fileContent) {
            onFileLoad(fileContent);
        }
    }, [fileContent]);

    return (
        <div>
            <input type="file" onChange={handleFileChange} />
            {fileName && <p>Đã chọn: {fileName}</p>}
        </div>
    );
};

export default FileUpload;
