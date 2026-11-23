{{/* Expand the name of the chart. */}}
{{- define "sts.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Create a default fully qualified app name. */}}
{{- define "sts.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/* Create chart name and version as used by the chart label. */}}
{{- define "sts.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Common labels. */}}
{{- define "sts.labels" -}}
helm.sh/chart: {{ include "sts.chart" . }}
{{ include "sts.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/* Selector labels. */}}
{{- define "sts.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sts.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/* Create the name of the service account to use. */}}
{{- define "sts.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "sts.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/* Normalize the Helm map or Fasit JSON string before rendering config and egress. */}}
{{- define "sts.externalIssuers" -}}
{{- $issuers := .Values.config.authorizationServer.externalIssuers -}}
{{- if kindIs "invalid" $issuers -}}
  {{- $issuers = dict -}}
{{- else if kindIs "string" $issuers -}}
  {{- $issuers = default "{}" $issuers | mustFromJson -}}
{{- end -}}
{{- if not (kindIs "map" $issuers) -}}
  {{- fail "config.authorizationServer.externalIssuers must be a map or JSON object mapping aliases to issuer URLs" -}}
{{- end -}}
{{- range $alias, $url := $issuers -}}
  {{- if not (kindIs "string" $url) -}}
    {{- fail (printf "config.authorizationServer.externalIssuers: issuer URL for alias %q must be a string" $alias) -}}
  {{- end -}}
{{- end -}}
{{- mustToJson $issuers -}}
{{- end -}}
