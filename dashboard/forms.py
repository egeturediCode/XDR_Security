from django import forms

from ingest.models import Assets, Company


class CompanyForm(forms.ModelForm):
    class Meta:
        model = Company
        fields = ["name", "address", "contact_email", "contact_phone", "is_active"]
        labels = {
            "name": "Şirket adı",
            "address": "Adres",
            "contact_email": "İletişim e-postası",
            "contact_phone": "İletişim telefonu",
            "is_active": "Aktif",
        }
        widgets = {
            "name": forms.TextInput(attrs={"placeholder": "Örn: Gamma Teknoloji", "autocomplete": "off"}),
            "address": forms.Textarea(attrs={"rows": 2, "placeholder": "Semt, şehir"}),
            "contact_email": forms.EmailInput(attrs={"placeholder": "guvenlik@sirket.com"}),
            "contact_phone": forms.TextInput(attrs={"placeholder": "+90 555 000 00 00"}),
        }

    def clean_name(self):
        name = self.cleaned_data["name"].strip()
        if Company.objects.filter(name__iexact=name).exists():
            raise forms.ValidationError("Bu isimde bir şirket zaten kayıtlı.")
        return name


class AssetRowForm(forms.ModelForm):
    class Meta:
        model = Assets
        fields = ["hostname", "ip_address", "mac_address", "asset_type", "criticality", "is_public"]
        labels = {
            "hostname": "Cihaz adı",
            "ip_address": "IP adresi",
            "mac_address": "MAC adresi",
            "asset_type": "Varlık türü",
            "criticality": "Kritiklik",
            "is_public": "İnternete açık",
        }
        widgets = {
            "hostname": forms.TextInput(attrs={"placeholder": "srv-db-01", "autocomplete": "off"}),
            "ip_address": forms.TextInput(attrs={"placeholder": "10.0.0.15"}),
            "mac_address": forms.TextInput(attrs={"placeholder": "AA:BB:CC:DD:EE:FF"}),
        }

    def clean_hostname(self):
        return self.cleaned_data["hostname"].strip()


class BaseAssetFormSet(forms.BaseFormSet):
    def clean(self):
        seen = set()
        for form in self.forms:
            hostname = form.cleaned_data.get("hostname") if hasattr(form, "cleaned_data") else None
            if not hostname:
                continue
            key = hostname.lower()
            if key in seen:
                form.add_error("hostname", "Bu cihaz adı listede birden fazla kez var.")
            seen.add(key)


AssetFormSet = forms.formset_factory(AssetRowForm, formset=BaseAssetFormSet, extra=0)
