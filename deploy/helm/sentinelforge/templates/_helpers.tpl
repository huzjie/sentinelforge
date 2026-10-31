{{- define "sentinelforge.fullname" -}}
{{- printf "%s-%s" .Release.Name "sentinelforge" | trunc 63 | trimSuffix "-" -}}
{{- end -}}
