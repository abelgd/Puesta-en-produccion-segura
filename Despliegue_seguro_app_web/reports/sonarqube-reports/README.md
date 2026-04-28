# Evidencias SonarQube - SAST

En esta carpeta se incluyen las capturas del análisis SAST realizado sobre la aplicación con **SonarQube Community Edition**, ejecutado en local mediante Docker y analizado con **SonarScanner CLI**.

## Archivos incluidos

- `overview.png`: vista general del proyecto analizado en SonarQube.
- `issues.png`: listado de issues detectados durante el análisis.
- `security.png`: security hotspot detectado en la configuración de CORS.

## Resumen del análisis

El proyecto superó el **Quality Gate** con estado **Passed**, por lo que el análisis general fue satisfactorio.  
SonarQube detectó **1 issue de seguridad**, **7 issues de fiabilidad**, **11 issues de mantenibilidad** y **1 security hotspot**.  
También se observó que no había duplicación de código y que la cobertura de tests era del **0.0%** en el momento del análisis.

## Hallazgos principales

En la vista de issues se aprecia un problema crítico relacionado con la exposición de un token de SonarQube en el archivo `sonar-project.properties`, además de varios problemas de mantenibilidad como código comentado y funciones anónimas.  
En la vista de seguridad se detectó un **Security Hotspot** por el uso de `app.use(cors())` sin una configuración restrictiva de orígenes, lo que requiere revisión manual para asegurar una política CORS segura.

## Observaciones

El análisis se ejecutó en local con SonarQube levantado en `http://localhost:9000` y utilizando `sonar-scanner` desde la raíz del proyecto, que es el método recomendado por la documentación oficial para proyectos sin escáner específico de build system.  
Como mejora futura, se recomienda corregir los hallazgos detectados y añadir tests automáticos para mejorar la cobertura.