// main.js - MediTahlil uygulaması için JavaScript kodları

document.addEventListener('DOMContentLoaded', function() {
    // Tahlil yükleme formu için animasyon ve ilerleme çubuğu işlemleri
    setupFileUploadProgress();
    
    // Form doğrulama işlemleri
    setupFormValidation();
    
    // Tema değiştirme işlevselliği
    setupTheme();
    
    // Newsletter fonksiyonu
    setupNewsletter();
    
    // Ürün turu başlatma
    setupProductTour();
    
    // İpuçları kurulumu
    setupTips();
    
    // Yeni kullanıcı kontrolü ve tur başlatma
    const currentPage = getCurrentPage();
    const tourCompleted = localStorage.getItem('tour-completed-' + currentPage);
    const tourExited = localStorage.getItem('tour-exited-' + currentPage);
    
    if (isNewUser() && !tourCompleted && !tourExited) {
        setTimeout(function() {
            startProductTour();
        }, 1000);
    }
    
    // Tour başlatma düğmesi için olay dinleyicisi
    const tourButton = document.getElementById('start-tour-button');
    if (tourButton) {
        tourButton.addEventListener('click', function() {
            startProductTour();
        });
    }
    
    // Tema değişikliği dinleme
    document.addEventListener('themeChanged', function(e) {
        updateElementsForTheme(e.detail.theme);
    });
});

// Tema değişikliğinde element stillerini güncelle
function updateElementsForTheme(theme) {
    // Koyu tema için tüm metin renklerini kontrol et ve ayarla
    if (theme === 'dark') {
        // Özel olarak hedeflenmesi gereken elementleri seç
        const textElements = document.querySelectorAll('.text-dark, .text-body, table tbody tr td, .card-text, .card-title');
        textElements.forEach(el => {
            if (!el.classList.contains('text-primary') && 
                !el.classList.contains('text-success') && 
                !el.classList.contains('text-danger') && 
                !el.classList.contains('text-warning') && 
                !el.classList.contains('text-info')) {
                el.style.color = '#ffffff';
            }
        });
        
        // Tablo metinlerini güncelle
        const tableTexts = document.querySelectorAll('table th, table td');
        tableTexts.forEach(el => {
            el.style.color = '#ffffff';
        });
        
        // Form etiketlerini güncelle
        const formLabels = document.querySelectorAll('label, .form-label');
        formLabels.forEach(el => {
            el.style.color = '#ffffff';
        });
    } else {
        // Açık temaya geçişte özel renklendirmeleri kaldır
        const textElements = document.querySelectorAll('.text-dark, .text-body, table tbody tr td, .card-text, .card-title');
        textElements.forEach(el => {
            el.style.color = '';
        });
        
        // Tablo metinlerini sıfırla
        const tableTexts = document.querySelectorAll('table th, table td');
        tableTexts.forEach(el => {
            el.style.color = '';
        });
        
        // Form etiketlerini sıfırla
        const formLabels = document.querySelectorAll('label, .form-label');
        formLabels.forEach(el => {
            el.style.color = '';
        });
    }
}

// Tema sistemi kurulumu 
function setupTheme() {
    const savedTheme = localStorage.getItem('theme');
    
    if (savedTheme) {
        document.documentElement.setAttribute('data-bs-theme', savedTheme);
        
        // Tema değiştirme düğmesinin ikonunu güncelle
        updateThemeIcon(savedTheme);
    } else {
        // Varsayılan tema: light - Sistem temasını kontrol etme
        localStorage.setItem('theme', 'light');
        document.documentElement.setAttribute('data-bs-theme', 'light');
        updateThemeIcon('light');
    }
    
    // Tema değiştirme düğmesine olay dinleyicisi ekleme
    const themeToggleBtn = document.getElementById('theme-toggle');
    if (themeToggleBtn) {
        themeToggleBtn.addEventListener('click', toggleTheme);
    }
}

// Tema ikonu güncelleme
function updateThemeIcon(theme) {
    const themeToggleBtn = document.getElementById('theme-toggle');
    if (themeToggleBtn) {
        const themeIcon = themeToggleBtn.querySelector('i');
        if (themeIcon) {
            themeIcon.className = theme === 'dark' ? 'bi bi-sun' : 'bi bi-moon';
        }
    }
}

// Tema değiştirme fonksiyonu
function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-bs-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    
    document.documentElement.setAttribute('data-bs-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    
    // İkonu güncelle
    updateThemeIcon(newTheme);
    
    // Stil güncellemesi için tüm sayfaya değişiklik bildir
    document.dispatchEvent(new CustomEvent('themeChanged', { detail: { theme: newTheme } }));
    
    // Tema değişimini bildirme
    const toastMessage = newTheme === 'dark' ? 'Koyu tema aktifleştirildi' : 'Açık tema aktifleştirildi';
    showToast(toastMessage);
}

// Bildirim gösterme fonksiyonu
function showToast(message, duration = 3000) {
    const toast = document.createElement('div');
    toast.className = 'toast align-items-center text-white bg-primary border-0';
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'assertive');
    toast.setAttribute('aria-atomic', 'true');
    
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">${message}</div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
        </div>
    `;
    
    let toastContainer = document.querySelector('.toast-container');
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.className = 'toast-container position-fixed bottom-0 end-0 p-3';
        document.body.appendChild(toastContainer);
    }
    
    toastContainer.appendChild(toast);
    
    const bsToast = new bootstrap.Toast(toast);
    bsToast.show();
    
    // Otomatik kaldırma
    setTimeout(() => {
        bsToast.hide();
        setTimeout(() => {
            toast.remove();
        }, 500);
    }, duration);
}

/**
 * Tahlil yükleme sırasında ilerleme çubuğunu ayarlar
 */
function setupFileUploadProgress() {
    // Analiz formunu seç
    const form = document.getElementById('tahlil-upload-form');
    const progressContainer = document.getElementById('progress-container');
    const progressBar = document.getElementById('progress-bar');
    const progressText = document.getElementById('progress-text');
    const submitButton = document.getElementById('submit-button');
    const analyzingMessage = document.getElementById('analyzing-message');
    const errorContainer = document.getElementById('error-container');
    const analyzingMessageText = document.getElementById('analyzing-message-text');
    
    // Form yoksa çık
    if (!form) return;
    
    // Form gönderildiğinde
    form.addEventListener('submit', function(e) {
        e.preventDefault();
        
        // Form doğrulama
        if (!validateForm(form)) {
            return false;
        }
        
        // Dosya kontrolü
        const fileInput = form.querySelector('input[type="file"]');
        if (!fileInput || !fileInput.files || fileInput.files.length === 0) {
            showErrorMessage(errorContainer, 'Lütfen bir dosya seçin.');
            return false;
        }
        
        // PDF kontrolü
        const file = fileInput.files[0];
        if (!file.name.toLowerCase().endsWith('.pdf')) {
            showErrorMessage(errorContainer, 'Lütfen sadece PDF dosyası yükleyin.');
            return false;
        }
        
        // Dosya boyutu kontrolü (max 10MB)
        if (file.size > 10 * 1024 * 1024) {
            showErrorMessage(errorContainer, 'Dosya boyutu 10MB\'dan büyük olamaz.');
            return false;
        }
        
        // Hata mesajını gizle
        hideErrorMessage(errorContainer);
        
        // İlerleme çubuğunu göster
        progressContainer.classList.remove('d-none');
        
        // Yükleme düğmesini devre dışı bırak
        if (submitButton) {
            submitButton.disabled = true;
            submitButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Yükleniyor...';
        }
        
        // Form verilerini oluştur
        const formData = new FormData(form);
        const xhr = new XMLHttpRequest();
        
        xhr.open('POST', form.action, true);
        xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
        
        // İlerleme çubuğu güncelleme
        xhr.upload.onprogress = function(e) {
            if (e.lengthComputable) {
                const percentComplete = Math.round((e.loaded / e.total) * 100);
                progressBar.style.width = percentComplete + '%';
                progressBar.setAttribute('aria-valuenow', percentComplete);
                progressText.textContent = percentComplete + '%';
            }
        };
        
        // Dosya yükleme tamamlandı, analiz başlıyor
        xhr.upload.onload = function() {
            progressBar.classList.add('bg-success');
            progressText.textContent = '100% - Tahlil analiz ediliyor...';
            
            // Analiz mesajını göster
            analyzingMessage.classList.remove('d-none');
            
            // Analiz için farklı mesajlar gösterme - kullanıcı deneyimini iyileştirme
            const analyzeMessages = [
                "Tahlil verileriniz yapay zeka ile analiz ediliyor...",
                "Değerler inceleniyor ve yorumlanıyor...",
                "Referans aralıkları karşılaştırılıyor...",
                "Sağlık değerlendirmesi oluşturuluyor...",
                "Son kontroller yapılıyor..."
            ];
            
            let messageIndex = 0;
            const messageInterval = setInterval(function() {
                if (messageIndex < analyzeMessages.length) {
                    analyzingMessageText.textContent = analyzeMessages[messageIndex];
                    messageIndex++;
                } else {
                    clearInterval(messageInterval);
                }
            }, 3000);
        };
        
        // Yanıt alındı
        xhr.onload = function() {
            if (xhr.status === 200) {
                try {
                    const response = JSON.parse(xhr.responseText);
                    if (response.success) {
                        // Başarılı mesajı göster
                        showToast('Tahlil başarıyla analiz edildi!');
                        
                        // Analiz sayfasına yönlendir
                        window.location.href = response.redirect;
                    } else {
                        showErrorMessage(errorContainer, response.error || 'Bir hata oluştu, lütfen tekrar deneyin.');
                        resetUploadForm(progressContainer, progressBar, progressText, submitButton, analyzingMessage);
                    }
                } catch (e) {
                    showErrorMessage(errorContainer, 'Sunucu yanıtı işlenemedi.');
                    resetUploadForm(progressContainer, progressBar, progressText, submitButton, analyzingMessage);
                }
            } else {
                try {
                    const response = JSON.parse(xhr.responseText);
                    showErrorMessage(errorContainer, response.error || 'HTTP Hata: ' + xhr.status);
                } catch (e) {
                    showErrorMessage(errorContainer, 'HTTP Hata: ' + xhr.status);
                }
                resetUploadForm(progressContainer, progressBar, progressText, submitButton, analyzingMessage);
            }
        };
        
        // Bağlantı hatası
        xhr.onerror = function() {
            showErrorMessage(errorContainer, 'Ağ hatası, lütfen internet bağlantınızı kontrol edin.');
            resetUploadForm(progressContainer, progressBar, progressText, submitButton, analyzingMessage);
        };
        
        // Zaman aşımı
        xhr.ontimeout = function() {
            showErrorMessage(errorContainer, 'Sunucu yanıt vermedi, lütfen daha sonra tekrar deneyin.');
            resetUploadForm(progressContainer, progressBar, progressText, submitButton, analyzingMessage);
        };
        
        // İstek gönder
        xhr.send(formData);
    });
}

/**
 * Hata mesajını gösterme
 */
function showErrorMessage(container, message) {
    if (container) {
        const alertText = container.querySelector('.alert-text');
        if (alertText) {
            alertText.textContent = message;
        }
        container.classList.remove('d-none');
    }
}

/**
 * Hata mesajını gizleme
 */
function hideErrorMessage(container) {
    if (container) {
        container.classList.add('d-none');
    }
}

/**
 * Yükleme formunu sıfırlar
 */
function resetUploadForm(progressContainer, progressBar, progressText, submitButton, analyzingMessage) {
    if (progressContainer) {
        progressContainer.classList.add('d-none');
    }
    
    if (progressBar) {
        progressBar.style.width = '0%';
        progressBar.setAttribute('aria-valuenow', 0);
        progressBar.classList.remove('bg-success');
    }
    
    if (progressText) {
        progressText.textContent = '0%';
    }
    
    if (submitButton) {
        submitButton.disabled = false;
        submitButton.innerHTML = '<i class="fas fa-robot me-2"></i>Analiz Et';
    }
    
    if (analyzingMessage) {
        analyzingMessage.classList.add('d-none');
    }
}

/**
 * Form doğrulama işlevini ayarlar
 */
function setupFormValidation() {
    // Tüm formları seç
    const forms = document.querySelectorAll('form.needs-validation');
    
    // Her bir form için olay dinleyicisi ekle
    Array.from(forms).forEach(function(form) {
        form.addEventListener('submit', function(event) {
            if (!validateForm(form)) {
                event.preventDefault();
                event.stopPropagation();
            }
        }, false);
        
        // Her input için anlık doğrulama
        const inputs = form.querySelectorAll('input, textarea, select');
        inputs.forEach(function(input) {
            input.addEventListener('blur', function() {
                validateInput(input);
            });
            
            input.addEventListener('change', function() {
                validateInput(input);
            });
        });
    });
}

/**
 * Bir formu doğrular
 * @param {HTMLFormElement} form - Doğrulanacak form
 * @returns {boolean} - Form geçerli mi
 */
function validateForm(form) {
    if (!form) return true;
    
    let isValid = true;
    const inputs = form.querySelectorAll('input, textarea, select');
    
    inputs.forEach(function(input) {
        if (!validateInput(input)) {
            isValid = false;
        }
    });
    
    // Formun classList'ine 'was-validated' ekle
    form.classList.add('was-validated');
    
    return isValid;
}

/**
 * Bir input alanını doğrular
 * @param {HTMLInputElement} input - Doğrulanacak input
 * @returns {boolean} - Input geçerli mi
 */
function validateInput(input) {
    if (!input) return true;
    
    // required kontrolü
    if (input.hasAttribute('required') && !input.value.trim()) {
        input.classList.add('is-invalid');
        input.classList.remove('is-valid');
        
        // Eğer feedback yoksa ekle
        let feedback = input.nextElementSibling;
        if (!feedback || !feedback.classList.contains('invalid-feedback')) {
            feedback = document.createElement('div');
            feedback.classList.add('invalid-feedback');
            feedback.textContent = 'Bu alan zorunludur.';
            input.parentNode.insertBefore(feedback, input.nextSibling);
        }
        
        return false;
    }
    
    // email kontrolü
    if (input.type === 'email' && input.value.trim()) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(input.value.trim())) {
            input.classList.add('is-invalid');
            input.classList.remove('is-valid');
            
            // Eğer feedback yoksa ekle
            let feedback = input.nextElementSibling;
            if (!feedback || !feedback.classList.contains('invalid-feedback')) {
                feedback = document.createElement('div');
                feedback.classList.add('invalid-feedback');
                feedback.textContent = 'Geçerli bir e-posta adresi girin.';
                input.parentNode.insertBefore(feedback, input.nextSibling);
            }
            
            return false;
        }
    }
    
    // password kontrolü (en az 6 karakter)
    if (input.type === 'password' && input.value.trim() && input.value.length < 6) {
        input.classList.add('is-invalid');
        input.classList.remove('is-valid');
        
        // Eğer feedback yoksa ekle
        let feedback = input.nextElementSibling;
        if (!feedback || !feedback.classList.contains('invalid-feedback')) {
            feedback = document.createElement('div');
            feedback.classList.add('invalid-feedback');
            feedback.textContent = 'Şifre en az 6 karakter olmalıdır.';
            input.parentNode.insertBefore(feedback, input.nextSibling);
        }
        
        return false;
    }
    
    // password_confirm kontrolü
    if (input.id === 'confirm_password') {
        const password = document.getElementById('password');
        if (password && input.value !== password.value) {
            input.classList.add('is-invalid');
            input.classList.remove('is-valid');
            
            // Eğer feedback yoksa ekle
            let feedback = input.nextElementSibling;
            if (!feedback || !feedback.classList.contains('invalid-feedback')) {
                feedback = document.createElement('div');
                feedback.classList.add('invalid-feedback');
                feedback.textContent = 'Şifreler eşleşmiyor.';
                input.parentNode.insertBefore(feedback, input.nextSibling);
            }
            
            return false;
        }
    }
    
    // Dosya türü kontrolü (.pdf)
    if (input.type === 'file' && input.value) {
        const fileName = input.value.toLowerCase();
        if (!fileName.endsWith('.pdf')) {
            input.classList.add('is-invalid');
            input.classList.remove('is-valid');
            
            // Eğer feedback yoksa ekle
            let feedback = input.nextElementSibling;
            if (!feedback || !feedback.classList.contains('invalid-feedback')) {
                feedback = document.createElement('div');
                feedback.classList.add('invalid-feedback');
                feedback.textContent = 'Lütfen sadece PDF dosyası yükleyin.';
                input.parentNode.insertBefore(feedback, input.nextSibling);
            }
            
            return false;
        }
    }
    
    // Geçerli input
    input.classList.remove('is-invalid');
    input.classList.add('is-valid');
    return true;
}

/**
 * Ürün turunu yapılandırır
 */
function setupProductTour() {
    // Intro.js konfigürasyonu
    introJs.setOptions({
        nextLabel: 'İleri',
        prevLabel: 'Geri',
        skipLabel: 'Atla',
        doneLabel: 'Tamam',
        hidePrev: true,
        hideNext: true,
        overlayOpacity: 0.8,
        showStepNumbers: true,
        keyboardNavigation: true,
        showProgress: true,
        scrollToElement: true,
        disableInteraction: false
    });
}

/**
 * Ürün turunu başlatır
 */
function startProductTour() {
    const currentPage = getCurrentPage();
    const tour = introJs();
    
    switch (currentPage) {
        case 'index':
            tour.setOptions({
                steps: [
                    {
                        title: 'MediTahlil\'e Hoş Geldiniz',
                        intro: 'MediTahlil ile kan tahlil sonuçlarınızı yapay zeka desteğiyle anında yorumlayabilirsiniz. Size hızlı bir tur gösterelim.'
                    },
                    {
                        element: '.navbar',
                        title: 'Navigasyon',
                        intro: 'Uygulamanın farklı bölümlerine buradan erişebilirsiniz.'
                    },
                    {
                        element: '#theme-toggle',
                        title: 'Tema Değiştirme',
                        intro: 'Koyu ve açık tema arasında geçiş yapabilirsiniz. Göz yorgunluğunu azaltmak için gece koyu temayı tercih edebilirsiniz.'
                    },
                    {
                        element: '.hero-section',
                        title: 'Tahlil Analizi',
                        intro: 'Kan tahlil sonuçlarınızı yükleyerek detaylı analiz alabilirsiniz.'
                    }
                ]
            });
            break;
        case 'analyze':
            tour.setOptions({
                steps: [
                    {
                        title: 'Tahlil Yükleme',
                        intro: 'Buradan kan tahlil sonuçlarınızı yükleyebilirsiniz.'
                    },
                    {
                        element: '.input-group',
                        title: 'Dosya Seçimi',
                        intro: 'PDF formatındaki kan tahlil sonuçlarınızı seçmek için tıklayın.'
                    },
                    {
                        element: '#progress-container',
                        title: 'İlerleme Durumu',
                        intro: 'Dosya yüklenirken bu ilerleme çubuğu yükleme durumunu gösterir.'
                    },
                    {
                        element: '#submit-button',
                        title: 'Analiz Başlatma',
                        intro: 'Dosyayı seçtikten sonra analizi başlatmak için bu butona tıklayın.'
                    },
                    {
                        element: '.list-group',
                        title: 'Yükleme İpuçları',
                        intro: 'Daha iyi sonuçlar için bu ipuçlarını dikkate alın.'
                    }
                ]
            });
            break;
        case 'dashboard':
            tour.setOptions({
                steps: [
                    {
                        title: 'Kontrol Paneli',
                        intro: 'Burada daha önce yüklediğiniz tüm tahlil sonuçlarını görüntüleyebilirsiniz.'
                    },
                    {
                        element: '.analysis-list',
                        title: 'Tahlil Sonuçları',
                        intro: 'Önceki analizlerinizin listesi burada bulunur. Detayları görmek için herhangi birine tıklayabilirsiniz.'
                    },
                    {
                        element: '.btn-primary',
                        title: 'Yeni Tahlil',
                        intro: 'Yeni bir tahlil yüklemek için bu butonu kullanabilirsiniz.'
                    },
                    {
                        element: '.statistics',
                        title: 'İstatistikler',
                        intro: 'Tahlil yükleme geçmişiniz ve analizlerinizle ilgili istatistikleri buradan görebilirsiniz.'
                    }
                ]
            });
            break;
        case 'result':
            tour.setOptions({
                steps: [
                    {
                        title: 'Tahlil Sonuçları',
                        intro: 'Tahlil sonuçlarınızın yapay zeka tarafından analiz edilmiş hali burada gösteriliyor.'
                    },
                    {
                        element: '.result-summary',
                        title: 'Özet',
                        intro: 'Tahlil sonuçlarınızın kısa bir özeti burada bulunur.'
                    },
                    {
                        element: '.result-details',
                        title: 'Detaylı Bilgi',
                        intro: 'Her bir değer için detaylı açıklamalar burada listelenir.'
                    },
                    {
                        element: '.recommendations',
                        title: 'Öneriler',
                        intro: 'Tahlil sonuçlarınıza göre öneriler burada listelenir. Unutmayın, bu sadece bir öneridir ve mutlaka doktorunuza danışmalısınız.'
                    },
                    {
                        element: '.btn-primary',
                        title: 'Yeni Analiz',
                        intro: 'Yeni bir tahlil yüklemek için bu butonu kullanabilirsiniz.'
                    }
                ]
            });
            break;
        case 'login':
            tour.setOptions({
                steps: [
                    {
                        title: 'Giriş Sayfası',
                        intro: 'Hesabınıza giriş yaparak tahlillerinizi yönetebilirsiniz.'
                    },
                    {
                        element: 'form',
                        title: 'Giriş Formu',
                        intro: 'Kullanıcı adınız ve şifrenizle giriş yapabilirsiniz.'
                    },
                    {
                        element: '.btn-primary',
                        title: 'Giriş Yap',
                        intro: 'Bilgilerinizi girdikten sonra giriş yapmak için bu butona tıklayın.'
                    }
                ]
            });
            break;
        case 'register':
            tour.setOptions({
                steps: [
                    {
                        title: 'Kayıt Sayfası',
                        intro: 'Yeni bir hesap oluşturarak MediTahlil hizmetlerinden faydalanabilirsiniz.'
                    },
                    {
                        element: 'form',
                        title: 'Kayıt Formu',
                        intro: 'Hesap oluşturmak için gerekli bilgileri doldurun.'
                    },
                    {
                        element: '.btn-primary',
                        title: 'Kayıt Ol',
                        intro: 'Bilgilerinizi girdikten sonra hesap oluşturmak için bu butona tıklayın.'
                    }
                ]
            });
            break;
        default:
            tour.setOptions({
                steps: [
                    {
                        title: 'MediTahlil',
                        intro: 'MediTahlil ile kan tahlil sonuçlarınızı kolayca analiz edebilirsiniz.'
                    },
                    {
                        element: '.navbar',
                        title: 'Navigasyon',
                        intro: 'Uygulamanın farklı bölümlerine buradan erişebilirsiniz.'
                    },
                    {
                        element: '#theme-toggle',
                        title: 'Tema Değiştirme',
                        intro: 'Koyu ve açık tema arasında geçiş yapabilirsiniz.'
                    }
                ]
            });
    }
    
    // Tur başlat
    tour.start();
    
    // Tur tamamlandığında veya atlandığında
    tour.oncomplete(function() {
        showToast('Tur tamamlandı! 👍');
        localStorage.setItem('tour-completed-' + currentPage, 'true');
    });
    
    tour.onexit(function() {
        localStorage.setItem('tour-exited-' + currentPage, 'true');
    });
}

/**
 * Mevcut sayfayı URL'den belirler
 * @returns {string} - Sayfa adı
 */
function getCurrentPage() {
    const path = window.location.pathname;
    
    if (path === '/') return 'index';
    
    // /analyze, /dashboard gibi sayfalar için
    const cleanPath = path.split('/')[1].split('?')[0]; // parametre ve uzantıları temizle
    if (cleanPath) return cleanPath;
    
    return 'index';
}

/**
 * İpuçları ekler
 */
function setupTips() {
    // Sayfa yüklendikten sonra ipuçlarını göster
    document.querySelectorAll('.tip-icon').forEach(function(tip) {
        // Üzerine gelindiğinde veya tıklandığında ipucu göster
        tip.addEventListener('mouseenter', function() {
            this.querySelector('.tip-content').style.display = 'block';
        });
        
        tip.addEventListener('mouseleave', function() {
            this.querySelector('.tip-content').style.display = 'none';
        });
        
        // Mobil için tıklama desteği
        tip.addEventListener('click', function(e) {
            e.preventDefault();
            const content = this.querySelector('.tip-content');
            content.style.display = content.style.display === 'block' ? 'none' : 'block';
        });
    });
    
    // Bağlama duyarlı ipuçları ekle
    addContextualTips();
}

/**
 * Bağlama duyarlı ipuçları ekler - kullanıcı deneyimini iyileştirmek için
 */
function addContextualTips() {
    const currentPage = getCurrentPage();
    
    // Tahlil yükleme sayfası için
    if (currentPage === 'analyze') {
        // Dosya giriş alanı için ipucu
        const fileInput = document.getElementById('pdf_file');
        if (fileInput) {
            fileInput.addEventListener('focus', function() {
                showToast('İpucu: Sadece PDF formatındaki tahlil sonuçlarını yükleyebilirsiniz.', 3000);
            });
        }
    }
    
    // Dashboard sayfası için
    if (currentPage === 'dashboard' && isNewUser()) {
        // Yeni kullanıcılar için özel ipucu göster
        showToast('İpucu: Tahlil yüklemek için "Tahlil Yükle" butonuna tıklayın.', 5000);
    }
    
    // Sonuç sayfası için
    if (currentPage === 'result') {
        // Sonuç sayfasında 5 saniye sonra ipucu göster
        setTimeout(function() {
            showToast('İpucu: Analiz sonuçlarını yazdırabilir veya PDF olarak kaydedebilirsiniz.', 4000);
        }, 5000);
    }
}

/**
 * Kullanıcının yeni olup olmadığını kontrol eder
 * @returns {boolean} - Kullanıcı yeni mi
 */
function isNewUser() {
    // body'deki data-new-user özelliğine bak
    return document.body.getAttribute('data-new-user') === 'true';
}

/**
 * Newsletter abone olma fonksiyonu
 */
function setupNewsletter() {
    const newsletterBtn = document.querySelector('.newsletter-btn');
    const newsletterInput = document.querySelector('.newsletter-input');
    
    if (newsletterBtn && newsletterInput) {
        newsletterBtn.addEventListener('click', function() {
            const email = newsletterInput.value.trim();
            
            // Email doğrulama
            if (!email) {
                showToast('Lütfen e-posta adresinizi girin.', 3000);
                return;
            }
            
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                showToast('Lütfen geçerli bir e-posta adresi girin.', 3000);
                return;
            }
            
            // Button loading durumu
            const originalText = newsletterBtn.innerHTML;
            newsletterBtn.disabled = true;
            newsletterBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Abone ol...';
            
            // Gerçek API çağrısı
            fetch('/newsletter/subscribe', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email: email })
            })
            .then(response => response.json())
            .then(data => {
                // Button'u eski haline getir
                newsletterBtn.disabled = false;
                newsletterBtn.innerHTML = originalText;
                
                if (data.success) {
                    showToast('🎉 ' + data.message, 5000);
                    newsletterInput.value = '';
                    
                    // Button'a başarı efekti ekle
                    newsletterBtn.style.background = 'linear-gradient(135deg, #10b981 0%, #059669 100%)';
                    newsletterBtn.style.color = 'white';
                    
                    // 3 saniye sonra ikinci bir mesaj göster
                    setTimeout(() => {
                        showToast('📧 Hoş geldin email\'i gönderildi! E-posta kutunuzu kontrol edin.', 4000);
                    }, 2000);
                    
                    setTimeout(() => {
                        newsletterBtn.style.background = '';
                        newsletterBtn.style.color = '';
                    }, 3000);
                } else {
                    showToast('❌ ' + data.message, 4000);
                }
            })
            .catch(error => {
                console.error('Newsletter API hatası:', error);
                
                // Button'u eski haline getir
                newsletterBtn.disabled = false;
                newsletterBtn.innerHTML = originalText;
                
                showToast('❌ Ağ hatası. Lütfen internet bağlantınızı kontrol edin.', 4000);
            });
        });
        
        // Enter tuşu ile abone olma
        newsletterInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                newsletterBtn.click();
            }
        });
        
        // Input focus animasyonu
        newsletterInput.addEventListener('focus', function() {
            this.style.transform = 'scale(1.02)';
            this.style.transition = 'all 0.3s ease';
        });
        
        newsletterInput.addEventListener('blur', function() {
            this.style.transform = 'scale(1)';
        });
    }
}