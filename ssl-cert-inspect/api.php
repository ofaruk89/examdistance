<?php
// api.php
// Hataları ekrana basma, JSON bozulmasın
error_reporting(0); 
require 'vendor/autoload.php';

use phpseclib3\File\X509;

header('Content-Type: application/json');

// Yardımcı Fonksiyon: phpseclib v3 ile CSR SAN Okuma (GELİŞTİRİLMİŞ VERSİYON)
function getCsrSansViaPhpseclib($csrContent) {
    try {
        $x509 = new X509();
        $csr = $x509->loadCSR($csrContent);

        if (!$csr) return 'Geçersiz CSR';

        $sans = [];
        
        // CSR Niteliklerini (Attributes) Gez
        if (isset($csr['certificationRequestInfo']['attributes'])) {
            foreach ($csr['certificationRequestInfo']['attributes'] as $attr) {
                $type = $attr['type'] ?? '';
                
                // KONTROL 1: Extension Request mi? (Hem OID hem İsim kontrolü ekledik)
                // 1.2.840.113549.1.9.14 = pkcs-9-at-extensionRequest
                if ($type === '1.2.840.113549.1.9.14' || $type === 'pkcs-9-at-extensionRequest' || $type === 'extensionRequest') {
                    
                    if (isset($attr['value'][0])) {
                        $extensions = $attr['value'][0];
                        
                        foreach ($extensions as $ext) {
                            $extId = $ext['extnId'] ?? '';
                            
                            // KONTROL 2: Subject Alt Name mi? (Hem OID hem İsim kontrolü)
                            // 2.5.29.17 = id-ce-subjectAltName
                            if ($extId === '2.5.29.17' || $extId === 'id-ce-subjectAltName' || $extId === 'subjectAltName') {
                                
                                if (isset($ext['extnValue'])) {
                                    foreach ($ext['extnValue'] as $altName) {
                                        // DNS İsimleri
                                        if (isset($altName['dNSName'])) {
                                            $sans[] = $altName['dNSName'];
                                        }
                                        // IP Adresleri (Nadiren kullanılır ama ekleyelim)
                                        if (isset($altName['iPAddress'])) {
                                            $sans[] = 'IP: ' . $altName['iPAddress'];
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if (empty($sans)) return 'Yok (Bu CSR sadece CN ile oluşturulmuş olabilir)';
        return implode('<br>', array_unique($sans));

    } catch (Exception $e) {
        return 'Okuma Hatası: ' . $e->getMessage();
    }
}

// Modulus Helper
function getModulusHash($resource, $type) {
    if (!$resource) return null;
    $details = openssl_pkey_get_details($resource);
    if (isset($details['rsa']['n'])) {
        return md5($details['rsa']['n']);
    }
    return null;
}

$response = [
    'chain_status' => [],
    'match_status' => ['cert_key' => 'waiting', 'cert_csr' => 'waiting'],
    'certificates' => [],
    'errors' => []
];

$certInput = $_POST['cert'] ?? '';
$keyInput = $_POST['key'] ?? '';
$csrInput = $_POST['csr'] ?? '';

// 1. SERTİFİKA PARSE
$certsRaw = [];
if (preg_match_all('/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/s', $certInput, $matches)) {
    $certsRaw = $matches[0];
}

$parsedCerts = [];
$certModulus = null;

foreach ($certsRaw as $index => $pem) {
    $x509 = openssl_x509_read($pem);
    if (!$x509) {
        $response['errors'][] = ($index + 1) . ". sertifika bozuk.";
        continue;
    }
    
    $parsed = openssl_x509_parse($x509);
    
    // Modulus Check (Leaf)
    if ($index === 0) {
        $pubKeyObj = openssl_pkey_get_public($x509);
        $certModulus = getModulusHash($pubKeyObj, 'cert');
    }

    // SAN Temizliği (Cert)
    $sanOutput = 'Yok';
    if (isset($parsed['extensions']['subjectAltName'])) {
        $sanList = explode(',', $parsed['extensions']['subjectAltName']);
        $cleanList = [];
        foreach ($sanList as $item) {
            $cleanList[] = str_replace('DNS:', '', trim($item));
        }
        $sanOutput = implode('<br>', $cleanList);
    }

    $parsedCerts[] = [
        'subject_cn' => $parsed['subject']['CN'] ?? 'N/A',
        'issuer_cn' => $parsed['issuer']['CN'] ?? 'N/A',
        'valid_from' => date('Y-m-d H:i:s', $parsed['validFrom_time_t']),
        'valid_to' => date('Y-m-d H:i:s', $parsed['validTo_time_t']),
        'serial' => $parsed['serialNumberHex'],
        'sans' => $sanOutput,
        'is_expired' => time() > $parsed['validTo_time_t'],
        'resource' => $x509
    ];
}

// 2. CHAIN CHECK
for ($i = 0; $i < count($parsedCerts) - 1; $i++) {
    $child = $parsedCerts[$i]['resource'];
    $parent = $parsedCerts[$i+1]['resource'];
    $verification = openssl_x509_verify($child, $parent);
    
    $response['chain_status'][] = [
        'status' => ($verification === 1) ? 'valid' : 'invalid'
    ];
}

foreach ($parsedCerts as &$p) { unset($p['resource']); }
$response['certificates'] = $parsedCerts;

// 3. PRIVATE KEY CHECK
if (!empty($keyInput)) {
    $pkey = openssl_pkey_get_private($keyInput);
    if ($pkey) {
        $keyModulus = getModulusHash($pkey, 'private');
        if ($certModulus && $keyModulus) {
             $response['match_status']['cert_key'] = ($certModulus === $keyModulus) ? 'success' : 'error';
        }
    } else {
         $response['errors'][] = "Key formatı hatalı.";
    }
}

// 4. CSR CHECK
$response['csr_info'] = null;
if (!empty($csrInput)) {
    $csrObj = openssl_csr_get_public_key($csrInput);
    if ($csrObj) {
        $subject = openssl_csr_get_subject($csrInput);
        
        // Gelişmiş SAN Okuma
        $csrSans = getCsrSansViaPhpseclib($csrInput);
        
        // Lokasyon Düzeltme
        $locParts = array_filter([$subject['L'] ?? null, $subject['ST'] ?? null]);
        $locString = implode(' / ', $locParts);

        // --- YENİ: Anahtar Detaylarını Al (RSA 2048 bit vs.) ---
        $pDetails = openssl_pkey_get_details($csrObj);
        $keyAlgo = 'Bilinmiyor';
        $keyBits = 0;

        if (isset($pDetails['rsa'])) {
            $keyAlgo = 'RSA';
            $keyBits = $pDetails['bits'];
        } elseif (isset($pDetails['ec'])) {
            $keyAlgo = 'ECC (Elliptic Curve)';
            $keyBits = $pDetails['bits']; // EC için key len
        } elseif (isset($pDetails['type']) && $pDetails['type'] == OPENSSL_KEYTYPE_DSA) {
             $keyAlgo = 'DSA';
             $keyBits = $pDetails['bits'];
        }

        $response['csr_info'] = [
            'cn' => $subject['CN'] ?? 'Belirtilmemiş',
            'org' => $subject['O'] ?? 'Belirtilmemiş',
            'unit' => $subject['OU'] ?? 'Belirtilmemiş',
            'country' => $subject['C'] ?? 'Belirtilmemiş',
            'loc' => $locString,
            'email' => $subject['emailAddress'] ?? 'Yok',
            'sans' => $csrSans,
            // Yeni Eklenenler
            'key_algo' => $keyAlgo,
            'key_bits' => $keyBits
        ];

        // Modulus Check
        $csrModulus = getModulusHash($csrObj, 'csr');
        $targetModulus = $keyModulus ?? $certModulus;
        
        if ($targetModulus && $csrModulus) {
            $response['match_status']['cert_csr'] = ($targetModulus === $csrModulus) ? 'success' : 'error';
        }
    } else {
        $response['errors'][] = "CSR formatı hatalı.";
    }
}

echo json_encode($response);