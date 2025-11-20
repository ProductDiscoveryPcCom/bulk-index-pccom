import streamlit as st
import json
import re
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from datetime import datetime
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import time


@dataclass
class BatchResult:
    """Resultado de una operación de indexación"""
    url: str
    success: bool
    message: str
    timestamp: str


class URLValidator:
    """Validador de URLs"""
    
    URL_PATTERN = re.compile(
        r'^https?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'
        r'localhost|'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE
    )
    
    @classmethod
    def validate_url(cls, url: str) -> Tuple[bool, str]:
        """
        Valida una URL individual
        Returns: (is_valid, error_message)
        """
        if not url or not url.strip():
            return False, "URL vacía"
        
        url = url.strip()
        
        if not cls.URL_PATTERN.match(url):
            return False, "Formato de URL inválido"
        
        if len(url) > 2048:
            return False, "URL demasiado larga (máx 2048 caracteres)"
        
        return True, ""
    
    @classmethod
    def validate_urls(cls, urls: List[str]) -> Tuple[List[str], List[Tuple[str, str]]]:
        """
        Valida una lista de URLs
        Returns: (urls_válidas, [(url_inválida, razón)])
        """
        valid_urls = []
        invalid_urls = []
        seen = set()
        
        for i, url in enumerate(urls, 1):
            url = url.strip()
            
            if not url:
                continue
                
            # Detectar duplicados
            if url in seen:
                invalid_urls.append((url, f"URL duplicada (línea {i})"))
                continue
            
            is_valid, error = cls.validate_url(url)
            if is_valid:
                valid_urls.append(url)
                seen.add(url)
            else:
                invalid_urls.append((url, f"{error} (línea {i})"))
        
        return valid_urls, invalid_urls


class GoogleIndexingService:
    """Servicio para interactuar con Google Indexing API"""
    
    BATCH_SIZE = 200  # Límite de Google API
    SCOPES = ["https://www.googleapis.com/auth/indexing"]
    
    def __init__(self, json_key_content: dict):
        """Inicializa el servicio con las credenciales"""
        try:
            self.credentials = service_account.Credentials.from_service_account_info(
                json_key_content, scopes=self.SCOPES
            )
            self.service = build('indexing', 'v3', credentials=self.credentials)
        except Exception as e:
            raise ValueError(f"Error al configurar credenciales: {str(e)}")
    
    @staticmethod
    def chunk_list(lst: List, chunk_size: int) -> List[List]:
        """Divide una lista en chunks del tamaño especificado"""
        return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]
    
    def submit_urls(self, urls: List[str], request_type: str, 
                    progress_callback=None) -> List[BatchResult]:
        """
        Envía URLs a Google Indexing API en batches
        
        Args:
            urls: Lista de URLs a procesar
            request_type: 'URL_UPDATED' o 'URL_DELETED'
            progress_callback: Función opcional para reportar progreso
        
        Returns:
            Lista de BatchResult con los resultados
        """
        all_results = []
        chunks = self.chunk_list(urls, self.BATCH_SIZE)
        total_chunks = len(chunks)
        
        for chunk_idx, chunk in enumerate(chunks, 1):
            if progress_callback:
                progress_callback(chunk_idx, total_chunks, len(chunk))
            
            results = self._submit_batch(chunk, request_type)
            all_results.extend(results)
            
            # Pequeña pausa entre batches para no saturar la API
            if chunk_idx < total_chunks:
                time.sleep(1)
        
        return all_results
    
    def _submit_batch(self, urls: List[str], request_type: str) -> List[BatchResult]:
        """Envía un batch de URLs y retorna los resultados"""
        results = []
        batch_results = {}
        
        def callback(request_id, response, exception):
            """Callback para procesar respuestas del batch"""
            url = batch_results.get(request_id, "unknown")
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            if exception is not None:
                if isinstance(exception, HttpError):
                    error_msg = f"HTTP {exception.resp.status}: {exception.error_details}"
                else:
                    error_msg = str(exception)
                results.append(BatchResult(url, False, error_msg, timestamp))
            else:
                success_msg = f"Indexada correctamente"
                results.append(BatchResult(url, True, success_msg, timestamp))
        
        try:
            batch = self.service.new_batch_http_request(callback=callback)
            
            for idx, url in enumerate(urls):
                request_id = str(idx)
                batch_results[request_id] = url
                batch.add(
                    self.service.urlNotifications().publish(
                        body={"url": url, "type": request_type}
                    ),
                    request_id=request_id
                )
            
            batch.execute()
            
        except Exception as e:
            # Si falla todo el batch, marcar todas las URLs como fallidas
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            for url in urls:
                results.append(BatchResult(url, False, f"Error en batch: {str(e)}", timestamp))
        
        return results


class SessionStateManager:
    """Maneja el estado de la sesión de Streamlit"""
    
    @staticmethod
    def initialize():
        """Inicializa las variables de session_state si no existen"""
        if 'results' not in st.session_state:
            st.session_state.results = None
        if 'last_execution' not in st.session_state:
            st.session_state.last_execution = None
    
    @staticmethod
    def save_results(results: List[BatchResult], request_type: str):
        """Guarda los resultados en session_state"""
        st.session_state.results = results
        st.session_state.last_execution = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'request_type': request_type,
            'total': len(results),
            'success': sum(1 for r in results if r.success),
            'failed': sum(1 for r in results if not r.success)
        }
    
    @staticmethod
    def clear_results():
        """Limpia los resultados guardados"""
        st.session_state.results = None
        st.session_state.last_execution = None


def display_results(results: List[BatchResult]):
    """Muestra los resultados de forma clara y organizada"""
    if not results:
        return
    
    success_count = sum(1 for r in results if r.success)
    failed_count = len(results) - success_count
    
    # Métricas
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total URLs", len(results))
    with col2:
        st.metric("Exitosas", success_count, delta=None if failed_count == 0 else "✓")
    with col3:
        st.metric("Fallidas", failed_count, delta=None if failed_count == 0 else "⚠️")
    
    # Tabs para resultados exitosos y fallidos
    tab1, tab2, tab3 = st.tabs(["✅ Exitosas", "❌ Fallidas", "📋 Todas"])
    
    with tab1:
        success_results = [r for r in results if r.success]
        if success_results:
            st.success(f"{len(success_results)} URLs indexadas correctamente")
            for r in success_results:
                st.text(f"✓ {r.url}")
        else:
            st.info("No hay URLs exitosas")
    
    with tab2:
        failed_results = [r for r in results if not r.success]
        if failed_results:
            st.error(f"{len(failed_results)} URLs fallaron")
            for r in failed_results:
                with st.expander(f"❌ {r.url}"):
                    st.code(r.message)
        else:
            st.success("No hay URLs fallidas")
    
    with tab3:
        for r in results:
            status = "✓" if r.success else "❌"
            with st.expander(f"{status} {r.url}"):
                st.write(f"**Estado:** {'Éxito' if r.success else 'Error'}")
                st.write(f"**Timestamp:** {r.timestamp}")
                st.write(f"**Mensaje:** {r.message}")
    
    # Botón de descarga
    export_data = "\n".join([
        f"{r.timestamp}|{'SUCCESS' if r.success else 'FAILED'}|{r.url}|{r.message}"
        for r in results
    ])
    st.download_button(
        label="📥 Descargar resultados (CSV)",
        data=export_data,
        file_name=f"indexing_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
        mime="text/plain"
    )


def main():
    st.set_page_config(
        page_title="Google Indexing API - Bulk Submission",
        page_icon="🔍",
        layout="wide"
    )
    
    st.title("🔍 Google Indexing API - Bulk URL Submission")
    st.markdown("---")
    
    # Inicializar session state
    SessionStateManager.initialize()
    
    # Sidebar con información
    with st.sidebar:
        st.header("ℹ️ Información")
        st.info(
            "**Límites de la API:**\n"
            "- Máximo 200 URLs por batch\n"
            "- Esta herramienta maneja automáticamente el chunking\n\n"
            "**Formato del archivo:**\n"
            "- Un URL por línea\n"
            "- URLs deben empezar con http:// o https://\n"
            "- Líneas vacías son ignoradas"
        )
        
        st.header("📊 Última ejecución")
        if st.session_state.last_execution:
            exec_info = st.session_state.last_execution
            st.write(f"**Hora:** {exec_info['timestamp']}")
            st.write(f"**Tipo:** {exec_info['request_type']}")
            st.write(f"**Total:** {exec_info['total']}")
            st.write(f"**✓ Exitosas:** {exec_info['success']}")
            st.write(f"**✗ Fallidas:** {exec_info['failed']}")
            
            if st.button("🗑️ Limpiar resultados"):
                SessionStateManager.clear_results()
                st.rerun()
        else:
            st.write("No hay ejecuciones previas")
    
    # Área principal
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.subheader("1️⃣ Credenciales")
        json_key = st.file_uploader(
            "Sube tu archivo JSON de service account",
            type="json",
            help="Archivo JSON con las credenciales de tu cuenta de servicio de Google"
        )
        
        if json_key:
            try:
                # Reset file pointer to beginning
                json_key.seek(0)
                json_key_content = json.load(json_key)
                if 'client_email' in json_key_content:
                    st.success(f"✓ Archivo válido: {json_key_content['client_email']}")
                    # Guardar en session_state para reutilizar
                    st.session_state.json_key_content = json_key_content
                else:
                    st.error("❌ El archivo JSON no parece ser una cuenta de servicio válida")
                    json_key = None
            except json.JSONDecodeError:
                st.error("❌ Error al leer el archivo JSON")
                json_key = None
    
    with col2:
        st.subheader("2️⃣ URLs")
        url_file = st.file_uploader(
            "Sube un archivo con URLs (una por línea)",
            type="txt",
            help="Archivo de texto con un URL por línea"
        )
        
        if url_file:
            try:
                content = url_file.read().decode('utf-8')
                urls_raw = [line.strip() for line in content.split('\n')]
                urls_raw = [url for url in urls_raw if url]  # Filtrar líneas vacías
                st.info(f"📄 {len(urls_raw)} líneas detectadas en el archivo")
            except Exception as e:
                st.error(f"❌ Error al leer el archivo: {str(e)}")
                url_file = None
    
    st.markdown("---")
    st.subheader("3️⃣ Configuración")
    
    col1, col2 = st.columns([1, 2])
    
    with col1:
        request_type = st.radio(
            "Tipo de operación:",
            ("URL_UPDATED", "URL_DELETED"),
            help="URL_UPDATED: Notifica a Google que el contenido se actualizó\n"
                 "URL_DELETED: Notifica a Google que el contenido se eliminó"
        )
    
    with col2:
        st.info(
            f"**{'🔄 URL_UPDATED' if request_type == 'URL_UPDATED' else '🗑️ URL_DELETED'}**\n\n"
            f"{'Usa esta opción para notificar a Google que el contenido de las URLs se ha actualizado o es nuevo.' if request_type == 'URL_UPDATED' else 'Usa esta opción para notificar a Google que el contenido de las URLs ha sido eliminado.'}"
        )
    
    # Botón de validación y envío
    if json_key and url_file:
        st.markdown("---")
        
        if st.button("🔍 Validar URLs", type="primary", use_container_width=True):
            with st.spinner("Validando URLs..."):
                valid_urls, invalid_urls = URLValidator.validate_urls(urls_raw)
                
                if valid_urls:
                    st.success(f"✅ {len(valid_urls)} URLs válidas encontradas")
                    
                    # Calcular batches necesarios
                    num_batches = (len(valid_urls) + 199) // 200
                    st.info(f"📦 Se procesarán en {num_batches} batch(es) de máximo 200 URLs cada uno")
                    
                    # Mostrar preview
                    with st.expander("👀 Preview de URLs válidas (primeras 10)"):
                        for url in valid_urls[:10]:
                            st.text(f"✓ {url}")
                        if len(valid_urls) > 10:
                            st.text(f"... y {len(valid_urls) - 10} más")
                
                if invalid_urls:
                    st.warning(f"⚠️ {len(invalid_urls)} URLs inválidas o duplicadas encontradas")
                    with st.expander("❌ URLs rechazadas"):
                        for url, reason in invalid_urls:
                            st.text(f"✗ {url}")
                            st.caption(f"   Razón: {reason}")
                
                if not valid_urls:
                    st.error("❌ No se encontraron URLs válidas para procesar")
                else:
                    # Guardar URLs válidas en session state para el envío
                    st.session_state.validated_urls = valid_urls
                    st.session_state.ready_to_submit = True
        
        # Botón de envío (solo aparece si hay URLs validadas)
        if st.session_state.get('ready_to_submit', False):
            st.markdown("###")
            if st.button("🚀 ENVIAR A GOOGLE", type="primary", use_container_width=True):
                validated_urls = st.session_state.validated_urls
                
                # Verificar que las credenciales están disponibles
                if 'json_key_content' not in st.session_state:
                    st.error("❌ Error: Las credenciales JSON no están disponibles. Por favor, vuelve a subir el archivo JSON.")
                    st.session_state.ready_to_submit = False
                    st.stop()
                
                try:
                    # Crear servicio usando JSON guardado en session_state
                    json_key_content = st.session_state.json_key_content
                    indexing_service = GoogleIndexingService(json_key_content)
                    
                    # Progress bar
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    
                    def update_progress(current_batch, total_batches, urls_in_batch):
                        progress = current_batch / total_batches
                        progress_bar.progress(progress)
                        status_text.text(
                            f"Procesando batch {current_batch}/{total_batches} "
                            f"({urls_in_batch} URLs)..."
                        )
                    
                    # Enviar URLs
                    results = indexing_service.submit_urls(
                        validated_urls,
                        request_type,
                        progress_callback=update_progress
                    )
                    
                    # Limpiar progress bar
                    progress_bar.empty()
                    status_text.empty()
                    
                    # Guardar resultados
                    SessionStateManager.save_results(results, request_type)
                    
                    # Limpiar flag de validación
                    st.session_state.ready_to_submit = False
                    
                    st.success("✅ Proceso completado!")
                    st.rerun()
                    
                except ValueError as e:
                    st.error(f"❌ Error de configuración: {str(e)}")
                except Exception as e:
                    st.error(f"❌ Error inesperado: {str(e)}")
    
    else:
        st.info("👆 Por favor, sube los archivos necesarios para comenzar")
    
    # Mostrar resultados si existen
    if st.session_state.results:
        st.markdown("---")
        st.subheader("📊 Resultados")
        display_results(st.session_state.results)


if __name__ == "__main__":
    main()
