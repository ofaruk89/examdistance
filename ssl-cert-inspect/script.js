/* script.js */

// Global zamanlayıcı değişkeni (Debounce için)
var timer;

$(document).ready(function() {
    // 1. ANALİZ TETİKLEYİCİSİ
    // Input alanlarına veri girildiğinde veya yapıştırıldığında çalışır
    $('#certInput, #keyInput, #csrInput').on('input paste', function() {
        // Hızlı yazma sırasında sunucuyu yormamak için önceki zamanlayıcıyı iptal et
        clearTimeout(timer);
        // 500ms (yarım saniye) bekle, sonra analizi başlat
        timer = setTimeout(analyze, 500);
    });

    // 2. KOPYALAMA BUTONU İŞLEVİ
    // Accordion menüsündeki "Kopyala" butonlarını yönetir
    $('.copy-btn').click(function() {
        let inputField = $(this).prev('.cmd-text');
        
        // Metni seç
        inputField.select();
        inputField[0].setSelectionRange(0, 99999); // Mobil uyumluluk için

        // Panoya kopyala
        navigator.clipboard.writeText(inputField.val()).then(() => {
            // Buton görsel geri bildirimi
            let originalText = $(this).text();
            let btn = $(this);
            
            btn.removeClass('btn-outline-secondary').addClass('btn-success').text('Kopyalandı!');
            
            // 2 saniye sonra eski haline dön
            setTimeout(() => {
                btn.removeClass('btn-success').addClass('btn-outline-secondary').text(originalText);
            }, 2000);
        });
    });
});

/**
 * API'ye istek atar ve sonuçları ekrana basar.
 */
function analyze() {
    let formData = {
        cert: $('#certInput').val(),
        key: $('#keyInput').val(),
        csr: $('#csrInput').val()
    };

    // Eğer alanlar boşsa bekleme ekranını göster
    if(formData.cert.trim() === "" && formData.csr.trim() === "") {
        $('#resultArea').html('<div class="gcp-card text-center py-5"><h5 class="text-muted">Analiz Bekleniyor...</h5><p class="text-muted small">Lütfen sol tarafa veri yapıştırın.</p></div>');
        $('#keyMatchStatus').html('');
        $('#csrMatchStatus').html('');
        return;
    }

    // AJAX İsteği
    $.post('api.php', formData, function(response) {
        let html = '';

        // --- 1. HATA YÖNETİMİ ---
        if(response.errors.length > 0) {
            html += '<div class="alert alert-danger shadow-sm border-0 mb-4">' + response.errors.join('<br>') + '</div>';
        }

        // --- 2. SERTİFİKA ZİNCİRİ RENDER ---
        if(response.certificates.length > 0) {
            response.certificates.forEach((cert, index) => {
                // Zincir Bağlantı Okları
                if(index > 0) {
                   let chainCheck = response.chain_status[index-1];
                   let iconClass = chainCheck.status === 'valid' ? 'chain-valid' : 'chain-invalid';
                   let iconText = chainCheck.status === 'valid' ? '✔ İmzalı (Güvenli Zincir)' : '✖ İmza Hatası (Kopuk)';
                   html += `<div class="chain-arrow"><i class="${iconClass}">${iconText}</i></div>`; 
                }

                // Kart Kenar Rengi (Süresi dolmuşsa kırmızı, geçerliyse yeşil)
                let borderStyle = cert.is_expired ? 'border-left: 5px solid #c5221f;' : 'border-left: 5px solid #137333;';

                html += `
                <div class="gcp-card" style="${borderStyle}">
                    <div class="gcp-header d-flex justify-content-between">
                        <span>${index === 0 ? '🍃 Leaf (Ana) Sertifika' : (index+1) + '. Zincir (Issuer)'}</span>
                        <span style="font-size:12px; font-family:monospace;">${cert.serial}</span>
                    </div>
                    <div class="row mb-2">
                        <div class="col-sm-4 info-label">Subject CN:</div>
                        <div class="col-sm-8 info-val"><strong>${cert.subject_cn}</strong></div>
                    </div>
                    <div class="row mb-2">
                        <div class="col-sm-4 info-label">SANs:</div>
                        <div class="col-sm-8 info-val">
                            <div class="scroll-box">${cert.sans}</div>
                        </div>
                    </div>
                    <div class="row mb-2">
                        <div class="col-sm-4 info-label">Issuer:</div>
                        <div class="col-sm-8 info-val">${cert.issuer_cn}</div>
                    </div>
                    <div class="row mb-2">
                        <div class="col-sm-4 info-label">Geçerlilik:</div>
                        <div class="col-sm-8 info-val">
                            <div class="mb-1">${cert.valid_from} — ${cert.valid_to}</div>
                            ${cert.is_expired ? '<span class="status-badge status-error">SÜRESİ DOLMUŞ</span>' : '<span class="status-badge status-success">GEÇERLİ</span>'}
                        </div>
                    </div>
                </div>`;
            });
        }
        
        // --- 3. CSR KARTI RENDER ---
        if (response.csr_info) {
            // Eğer yukarıda sertifika varsa araya ayırıcı koy
            if (response.certificates.length > 0) {
                html += '<div class="text-center my-3 text-muted" style="font-weight:500; letter-spacing:1px;">— VE —</div>';
            }

            html += `
            <div class="gcp-card" style="border-left: 5px solid #6f42c1;">
                <div class="gcp-header" style="color: #6f42c1;">
                    📝 CSR Detayları
                </div>
                
                <div class="row mb-2">
                    <div class="col-sm-4 info-label">CN:</div>
                    <div class="col-sm-8 info-val"><strong>${response.csr_info.cn}</strong></div>
                </div>

                <div class="row mb-2">
                    <div class="col-sm-4 info-label">Anahtar:</div>
                    <div class="col-sm-8 info-val">
                        <span class="badge bg-light text-dark border">${response.csr_info.key_algo}</span> 
                        <strong>${response.csr_info.key_bits} bit</strong>
                    </div>
                </div>
                
                <div class="row mb-2">
                    <div class="col-sm-4 info-label">Organizasyon:</div>
                    <div class="col-sm-8 info-val">${response.csr_info.org} / ${response.csr_info.unit}</div>
                </div>

                <div class="row mb-2">
                    <div class="col-sm-4 info-label">Lokasyon:</div>
                    <div class="col-sm-8 info-val">${response.csr_info.loc} - ${response.csr_info.country}</div>
                </div>

                 <div class="row mb-2">
                    <div class="col-sm-4 info-label">İstenen SANs:</div>
                    <div class="col-sm-8 info-val">
                        <div class="scroll-box">${response.csr_info.sans}</div>
                    </div>
                </div>
            </div>`;
        }

        $('#resultArea').html(html);

        // --- 4. EŞLEŞME DURUMLARI (Private Key & CSR) ---
        
        // Key vs Cert Durumu
        let keyStatusHtml = '';
        if(response.match_status.cert_key === 'success') {
            keyStatusHtml = '<div class="status-badge status-success w-100 justify-content-center">✓ Modulus Eşleşiyor</div>';
        } else if (response.match_status.cert_key === 'error') {
            keyStatusHtml = '<div class="status-badge status-error w-100 justify-content-center">✕ Private Key Uyumsuz</div>';
        }
        $('#keyMatchStatus').html(keyStatusHtml);

        // CSR vs Cert/Key Durumu
        let csrStatusHtml = '';
        if(response.match_status.cert_csr === 'success') {
            csrStatusHtml = '<div class="status-badge status-success w-100 justify-content-center">✓ Key/Cert ile Uyumlu</div>';
        } else if (response.match_status.cert_csr === 'error') {
            csrStatusHtml = '<div class="status-badge status-error w-100 justify-content-center">✕ Uyumsuz CSR</div>';
        }
        $('#csrMatchStatus').html(csrStatusHtml);

    }, 'json').fail(function() {
         $('#resultArea').html('<div class="alert alert-danger">Sunucu ile iletişim hatası oluştu (API.php yanıt vermedi).</div>');
    });
}