# 🏥 MedikalAI - Intelligent Blood Test Analysis

<div align="center">

![Python](https://img.shields.io/badge/python-v3.9+-blue.svg)
![Flask](https://img.shields.io/badge/flask-v2.3.3-green.svg)
![AI](https://img.shields.io/badge/AI-Gemini%202.0-orange.svg)
![License](https://img.shields.io/badge/license-Proprietary-red.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

**AI-powered blood test analysis platform that provides intelligent health insights**

[Demo](#demo) • [Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Contributing](#-contributing) • [Türkçe README](README_tr.md)

</div>


---

## ⚠️ **IMPORTANT LEGAL NOTICE**

<div align="center">

### 🚫 **PROPRIETARY SOFTWARE - ALL RIGHTS RESERVED** 🚫

**THIS IS NOT OPEN SOURCE SOFTWARE**

</div>

| ❌ **PROHIBITED** | ✅ **ALLOWED** |
|:---|:---|
| Commercial use | Code viewing for education |
| Copying/Cloning for use | Portfolio demonstration |
| Modification | Academic research |
| Distribution | Learning purposes only |
| Deployment | Local testing (personal use) |
| Creating derivatives | - |

> 🚨 **WARNING**: Unauthorized use of this software will result in immediate legal action including DMCA takedowns, copyright infringement claims, and monetary damages.

---

## 📖 About

MedikalAI is a sophisticated web application that leverages artificial intelligence to analyze blood test results and provide comprehensive health insights. Built with Flask and powered by Google's Gemini AI, it offers medical professionals and individuals an intuitive platform for understanding blood test parameters and potential health risks.

> ⚠️ **Medical Disclaimer**: This application is for informational purposes only and should not replace professional medical advice. Always consult with healthcare professionals for accurate diagnosis and treatment.

## 🎯 Features

### 🔬 Core Functionality
- **AI-Powered Analysis**: Intelligent blood test interpretation using Gemini 2.0 Flash
- **PDF Processing**: Extract data from blood test PDFs automatically  
- **Comprehensive Reports**: Detailed analysis with risk assessments and recommendations
- **Multi-Parameter Support**: 50+ blood test parameters across 8 categories

### 💊 Medical Coverage
- **🧬 Cancer Markers**: CEA, CA 15-3, CA 19-9, CA 125, PSA
- **🩸 Complete Blood Count**: Hemoglobin, WBC, Platelets, etc.
- **🫀 Lipid Profile**: Cholesterol, HDL, LDL, Triglycerides
- **🍬 Metabolism**: Glucose, HbA1c, Insulin levels
- **🧪 Hormones**: TSH, T3, T4, Vitamin D, B12
- **🍃 Liver Function**: ALT, AST, Bilirubin, Albumin
- **🔥 Inflammation**: CRP, ESR, Procalcitonin

### 🛡️ Platform Features
- **User Management**: Secure authentication with BCrypt
- **Admin Dashboard**: User and analysis management
- **Subscription System**: Tiered access levels
- **Dark/Light Theme**: Modern responsive UI
- **Multi-language**: Turkish interface
- **Email Integration**: Automated notifications

## 🛠️ Tech Stack

**Backend:**
- Python 3.9+
- Flask 2.3.3
- SQLite Database
- BCrypt Authentication
- JWT Tokens

**AI & Processing:**
- Google Gemini 2.0 Flash API
- PyPDF2 for PDF processing
- Custom medical algorithms

**Frontend:**
- Bootstrap 5
- JavaScript (ES6+)
- Responsive Design
- Progressive Web App features

**DevOps:**
- Docker & Docker Compose
- Fly.io deployment
- GitHub Actions (optional)

## 🚀 Installation

### Prerequisites
- Python 3.9 or higher
- pip package manager
- Git

### Local Development

1. **Clone the repository**
   ```bash
   git clone https://github.com/Yemresalcan/medikalai.git
   cd medikalai
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   # or
   venv\Scripts\activate     # Windows
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Environment setup**
   ```bash
   cp .env-example .env
   # Edit .env with your API keys
   ```

5. **Initialize database**
   ```bash
   python -c "from app import init_db; init_db()"
   ```

6. **Run the application**
   ```bash
   python app.py
   ```

   Visit `http://localhost:8080` in your browser.

### Docker Development

```bash
cd scripts/deployment
docker-compose up -d
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `GEMINI_API_KEY` | Google Gemini API key | ✅ | - |
| `SECRET_KEY` | Flask secret key | ❌ | auto-generated |
| `JWT_SECRET_KEY` | JWT signing key | ❌ | auto-generated |
| `EMAIL_PASSWORD` | Gmail app password | ❌ | - |
| `FLASK_DEBUG` | Debug mode | ❌ | False |
| `DB_PATH` | Database path | ❌ | `kan_tahlil_app.db` |

### Getting API Keys

1. **Gemini API Key**:
   - Visit [Google AI Studio](https://makersuite.google.com/app/apikey)
   - Create a new API key
   - Add to your `.env` file

## 💡 Usage

### Basic Analysis

1. **Register/Login** to your account
2. **Upload PDF** blood test report
3. **Review Analysis** with AI-generated insights
4. **Download Report** in PDF format

### Admin Features

- Access admin panel at `/admin/dashboard`
- Default credentials: `admin` / `admin123` (change immediately)
- Manage users, analyses, and newsletter subscribers

### API Endpoints

```bash
# Authentication
POST /api/login          # User login
GET  /api/analyses       # Get user analyses (JWT required)

# Web Interface
GET  /                   # Landing page
GET  /analyze            # Analysis page
GET  /dashboard          # User dashboard
GET  /admin/*            # Admin routes
```

## 📊 Demo

### Screenshots
<img width="1888" height="910" alt="image" src="https://github.com/user-attachments/assets/af81c2f7-3658-4051-96be-25fe158ba48d" />


*Blood Test Upload Interface*
- Modern drag-and-drop file upload
- Real-time processing indicators
- Mobile-responsive design

*AI Analysis Results*
<img width="1380" height="790" alt="image" src="https://github.com/user-attachments/assets/b7fd7268-f956-47c0-89e4-069911df68cd" />

- Comprehensive parameter breakdown
- Risk assessment visualization  
- Actionable health recommendations

*Admin Dashboard*


<img width="1879" height="914" alt="image" src="https://github.com/user-attachments/assets/9ad98d98-3a84-42f2-a05e-a6b62ddd9d08" />

- User management interface
- Analytics and statistics
- System health monitoring

## 🗂️ Project Structure

```
medikalai/
├── 📄 app.py                     # Main Flask application
├── ⚙️ config.py                  # Configuration settings
├── 📋 requirements.txt           # Python dependencies
├── 🗃️ kan_tahlil_app.db         # SQLite database
├── 📁 templates/                 # Jinja2 templates
│   ├── 📁 admin/                # Admin interface
│   ├── 📁 subscription/         # Subscription pages
│   └── 📄 *.html               # Web pages
├── 📁 static/                   # Static assets
│   ├── 📁 assets/              # Images and media
│   ├── 📁 js/                  # JavaScript files
│   └── 📁 favicon/             # Favicon files
└── 📁 scripts/                  # Deployment scripts
    ├── 📁 deployment/          # Docker & deployment
    └── 📁 docs/                # Documentation
```

## 🚫 Contributing

**CONTRIBUTIONS ARE NOT ACCEPTED**

This is proprietary software. We do **NOT** accept:
- Pull requests
- Issues
- Feature requests  
- Code contributions
- Documentation updates

For business inquiries or licensing discussions only, contact the author directly.

## 📝 License

**⚠️ PROPRIETARY SOFTWARE - ALL RIGHTS RESERVED**

This project is **NOT** open source. Usage, modification, distribution, and commercial use are **STRICTLY PROHIBITED** without explicit written permission.

See the [LICENSE](LICENSE) file for complete terms and restrictions.

**🚫 Unauthorized use will result in legal action**

## 👨‍💻 Author

**Yemresalcan**
- GitHub: [@Yemresalcan](https://github.com/Yemresalcan)
- WebSite: [Web-Site](https://yapaykume.vercel.app/)
- Email: yunusemresalcan@gmail.com

## 🙏 Acknowledgments

- Google Gemini AI for intelligent analysis
- Flask community for the robust framework
- Bootstrap team for the UI components
- Medical professionals for domain expertise

## 📈 Roadmap

- [ ] **Multi-language Support**: English, German, French
- [ ] **Mobile App**: Native iOS/Android applications  
- [ ] **API Integration**: Hospital system integrations
- [ ] **Advanced Analytics**: ML-powered trend analysis
- [ ] **Telemedicine**: Video consultation features
- [ ] **Wearable Integration**: Apple Health, Google Fit

---

<div align="center">

**⭐ Star this repository if you find it helpful!**

[Report Bug](https://github.com/Yemresalcan/medikalai/issues) • [Request Feature](https://github.com/Yemresalcan/medikalai/issues) • [Documentation](https://github.com/Yemresalcan/medikalai/wiki)

</div>
