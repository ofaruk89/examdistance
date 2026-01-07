<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSL Inspector & Toolset</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="style.css" rel="stylesheet">
</head>
<body>

<nav class="navbar-custom">
    <div class="container-fluid">
        <span class="navbar-brand">
            🔐 SSL Inspector <span style="font-size: 14px; color:#5f6368; font-weight:400;">| Ağ & Güvenlik Mühendisliği Araçları</span>
        </span>
    </div>
</nav>

<div class="container-fluid">
    <div class="row">
        <div class="col-lg-5 col-md-12">
            <div class="gcp-card">
                <div class="gcp-header">Sertifika Veri Girişi</div>
                
                <div class="mb-4">
                    <label class="form-label">Certificate (Chain dahil edilebilir)</label>
                    <textarea class="form-control" id="certInput" rows="6" placeholder="-----BEGIN CERTIFICATE-----..."></textarea>
                    <div class="form-text text-muted">Leaf > Intermediate > Root sırasıyla zincir yapıştırabilirsiniz.</div>
                </div>

                <div class="mb-4">
                    <label class="form-label">Private Key <span class="badge bg-light text-danger border border-danger">Hassas Veri</span></label>
                    <textarea class="form-control" id="keyInput" rows="4" placeholder="-----BEGIN PRIVATE KEY-----..."></textarea>
                    <div id="keyMatchStatus" class="mt-2"></div>
                </div>

                <div class="mb-3">
                    <label class="form-label">CSR (Certificate Signing Request)</label>
                    <textarea class="form-control" id="csrInput" rows="4" placeholder="-----BEGIN CERTIFICATE REQUEST-----..."></textarea>
                    <div id="csrMatchStatus" class="mt-2"></div>
                </div>
            </div>
        </div>

        <div class="col-lg-7 col-md-12">
            <div id="resultArea">
                <div class="gcp-card text-center py-5">
                    <h5 class="text-muted">Analiz Bekleniyor...</h5>
                    <p class="text-muted small">Lütfen sol tarafa Sertifika, Key veya CSR verisi yapıştırın.</p>
                </div>
            </div>
        </div>
    </div>

    <div class="row mt-4 mb-5">
        <div class="col-12">
            <div class="gcp-card">
                <div class="gcp-header d-flex justify-content-between align-items-center">
                    <span>🛠️ OpenSSL Hızlı Komut Kütüphanesi</span>
                    <span class="badge bg-secondary bg-opacity-10 text-secondary">Cheat Sheet</span>
                </div>
                
                <div class="accordion" id="opensslAccordion">

                    <div class="accordion-item">
                        <h2 class="accordion-header" id="headingOne">
                            <button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#collapseOne">
                                <strong>1. Anahtar ve CSR Oluşturma</strong>
                            </button>
                        </h2>
                        <div id="collapseOne" class="accordion-collapse collapse show" data-bs-parent="#opensslAccordion">
                            <div class="accordion-body">
                                <div class="cmd-row">
                                    <label class="cmd-label">Yeni Private Key Oluşturma (2048 bit)</label>
                                    <div class="input-group">
                                        <input type="text" class="form-control cmd-text" value="openssl genrsa -out key.key 2048" readonly>
                                        <button class="btn btn-outline-secondary copy-btn" type="button">Kopyala</button>
                                    </div>
                                </div>
                                <div class="cmd-row">
                                    <label class="cmd-label">Mevcut Key ile CSR Oluşturma</label>
                                    <div class="input-group">
                                        <input type="text" class="form-control cmd-text" value="openssl req -out CSR.csr -key key.key -new -sha256" readonly>
                                        <button class="btn btn-outline-secondary copy-btn" type="button">Kopyala</button>
                                    </div>
                                </div>
                                <div class="cmd-row">
                                    <label class="cmd-label">Mevcut Key ile SAN (Subject Alternative Name) CSR</label>
                                    <div class="input-group">
                                        <input type="text" class="form-control cmd-text" value="openssl req -out imzala.csr -key bkt.key -new -sha256 -config SAN.cnf" readonly>
                                        <button class="btn btn-outline-secondary copy-btn" type="button">Kopyala</button>
                                    </div>
                                    <small class="text-muted">ℹ️ <a href="san.cnf" download class="fw-bold text-decoration-none">san.cnf</a> dosyası gerektirir.</small>
                                </div>
                                <div class="cmd-row">
                                    <label class="cmd-label">Tek Satırda Yeni Key + SAN CSR</label>
                                    <div class="input-group">
                                        <input type="text" class="form-control cmd-text" value="openssl req -out sslcert.csr -newkey rsa:2048 -nodes -keyout private.key -config san.cnf" readonly>
                                        <button class="btn btn-outline-secondary copy-btn" type="button">Kopyala</button>
                                    </div>
                                    <small class="text-muted">ℹ️ <a href="san.cnf" download class="fw-bold text-decoration-none">san.cnf</a> dosyası gerektirir.</small>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="accordion-item">
                        <h2 class="accordion-header" id="headingTwo">
                            <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseTwo">
                                <strong>2. Format Dönüştürme (PFX, CER, PEM)</strong>
                            </button>
                        </h2>
                        <div id="collapseTwo" class="accordion-collapse collapse" data-bs-parent="#opensslAccordion">
                            <div class="accordion-body">
                                <div class="cmd-row">
                                    <label class="cmd-label">CRT ve Key dosyasını PFX'e Çevirme</label>
                                    <div class="input-group">
                                        <input type="text" class="form-control cmd-text" value="openssl pkcs12 -export -inkey key.key -in CPPS.crt -name CPPS -out CPPS.pfx" readonly>
                                        <button class="btn btn-outline-secondary copy-btn" type="button">Kopyala</button>
                                    </div>
                                </div>
                                <div class="cmd-row">
                                    <label class="cmd-label">PFX'ten Sertifikayı (CER) Dışarı Aktarma</label>
                                    <div class="input-group">
                                        <input type="text" class="form-control cmd-text" value="openssl pkcs12 -in cardtekCert.pfx -out cardtekCert.cer -nokeys -clcerts" readonly>
                                        <button class="btn btn-outline-secondary copy-btn" type="button">Kopyala</button>
                                    </div>
                                </div>
                                <div class="cmd-row">
                                    <label class="cmd-label">PFX'ten Private Key'i Dışarı Aktarma</label>
                                    <div class="input-group">
                                        <input type="text" class="form-control cmd-text" value="openssl pkcs12 -in filename.pfx -nocerts -out key.pem" readonly>
                                        <button class="btn btn-outline-secondary copy-btn" type="button">Kopyala</button>
                                    </div>
                                </div>
                                <div class="cmd-row">
                                    <label class="cmd-label">PEM Formatını DER'e Çevirme</label>
                                    <div class="input-group">
                                        <input type="text" class="form-control cmd-text" value="openssl x509 -inform pem -in cardtekCert.crt -outform der -out cardtekCert.cer" readonly>
                                        <button class="btn btn-outline-secondary copy-btn" type="button">Kopyala</button>
                                    </div>
                                </div>
                                <div class="cmd-row">
                                    <label class="cmd-label">DER Formatını PEM'e Çevirme</label>
                                    <div class="input-group">
                                        <input type="text" class="form-control cmd-text" value="openssl x509 -inform der -in infile.cer -out outfile.cer" readonly>
                                        <button class="btn btn-outline-secondary copy-btn" type="button">Kopyala</button>
                                    </div>
                                </div>
                                <div class="cmd-row">
                                    <label class="cmd-label">Sertifikaları P7B Formatına Çevirme</label>
                                    <div class="input-group">
                                        <input type="text" class="form-control cmd-text" value="openssl crl2pkcs7 -nocrl -certfile certificate.cer -certfile intermediate.cer -out certificate.p7b" readonly>
                                        <button class="btn btn-outline-secondary copy-btn" type="button">Kopyala</button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="accordion-item">
                        <h2 class="accordion-header" id="headingThree">
                            <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseThree">
                                <strong>3. Kontrol, Şifreleme ve Debug</strong>
                            </button>
                        </h2>
                        <div id="collapseThree" class="accordion-collapse collapse" data-bs-parent="#opensslAccordion">
                            <div class="accordion-body">
                                <div class="cmd-row">
                                    <label class="cmd-label">MD5 ile Eşleşme Kontrolü (Modulus Check)</label>
                                    <div class="input-group mb-1">
                                        <span class="input-group-text">Cert</span>
                                        <input type="text" class="form-control cmd-text" value="openssl x509 -noout -modulus -in certificate.crt | openssl md5" readonly>
                                        <button class="btn btn-outline-secondary copy-btn" type="button">Kopyala</button>
                                    </div>
                                    <div class="input-group mb-1">
                                        <span class="input-group-text">Key</span>
                                        <input type="text" class="form-control cmd-text" value="openssl rsa -noout -modulus -in privateKey.key | openssl md5" readonly>
                                        <button class="btn btn-outline-secondary copy-btn" type="button">Kopyala</button>
                                    </div>
                                    <div class="input-group">
                                        <span class="input-group-text">CSR</span>
                                        <input type="text" class="form-control cmd-text" value="openssl req -noout -modulus -in CSR.csr | openssl md5" readonly>
                                        <button class="btn btn-outline-secondary copy-btn" type="button">Kopyala</button>
                                    </div>
                                </div>
                                <div class="cmd-row">
                                    <label class="cmd-label">Key Dosyasından Şifreyi Kaldırma</label>
                                    <div class="input-group">
                                        <input type="text" class="form-control cmd-text" value="openssl rsa -in key.key -out key_unencrypted.key" readonly>
                                        <button class="btn btn-outline-secondary copy-btn" type="button">Kopyala</button>
                                    </div>
                                </div>
                                <div class="cmd-row">
                                    <label class="cmd-label">Key Dosyasını Şifreleme (AES256)</label>
                                    <div class="input-group">
                                        <input type="text" class="form-control cmd-text" value="openssl rsa -aes256 -in key.key -out key_encrypted.key" readonly>
                                        <button class="btn btn-outline-secondary copy-btn" type="button">Kopyala</button>
                                    </div>
                                </div>
                                <div class="cmd-row">
                                    <label class="cmd-label">CSR'ı Self-Signed Sertifikaya Çevirme</label>
                                    <div class="input-group">
                                        <input type="text" class="form-control cmd-text" value="openssl x509 -req -days 5475 -sha256 -in CSR.csr -signkey key.key -out CPPS.cer" readonly>
                                        <button class="btn btn-outline-secondary copy-btn" type="button">Kopyala</button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                </div>
            </div>
        </div>
    </div>
</div>

<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script src="script.js"></script>

</body>
</html>