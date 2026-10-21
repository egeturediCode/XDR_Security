from django import template

register = template.Library()

LABELS = {
    "critical": "Kritik",
    "high": "Yüksek",
    "medium": "Orta",
    "low": "Düşük",
    "informational": "Bilgi",
    "info": "Bilgi",
    "detected": "Tespit edildi",
    "correlated": "Korelasyonlu",
    "ingested": "Alındı",
    "open": "Açık",
    "investigating": "İnceleniyor",
    "resolved": "Çözüldü",
    "closed": "Kapatıldı",
    "false_positive": "Yanlış alarm",
}


@register.filter
def tr(value):
    return LABELS.get(str(value).lower(), value)
