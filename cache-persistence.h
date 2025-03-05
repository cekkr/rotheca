#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <filesystem>
#include <chrono>
#include <mutex>
#include <atomic>
#include <thread>
#include <queue>
#include <condition_variable>

// Classe per gestire la persistenza della cache su disco in modo asincrono
class PersistenceManager {
private:
    // Struttura per un job di scrittura
    struct WriteCacheJob {
        std::string cache_file;                 // Percorso del file di cache
        std::vector<byte> data;                 // Dati da scrivere
        uint64_t offset;                        // Offset nel file
        std::function<void(bool)> callback;     // Callback da chiamare al completamento
    };
    
    // Thread worker e sincronizzazione
    std::thread worker_thread;
    std::mutex queue_mutex;
    std::condition_variable condition;
    std::queue<WriteCacheJob> job_queue;
    std::atomic<bool> should_terminate{false};
    
    // Statistiche
    std::atomic<size_t> completed_jobs{0};
    std::atomic<size_t> failed_jobs{0};
    std::chrono::steady_clock::time_point last_flush;
    
    // Directory di cache
    std::string cache_directory;
    
    // Cache maintenance
    std::chrono::steady_clock::time_point last_maintenance;
    const std::chrono::seconds maintenance_interval{3600}; // Ogni ora
    const uint64_t max_cache_size = 1024 * 1024 * 1024;   // 1GB

    // Thread worker per processare i job in background
    void worker_function() {
        while (!should_terminate) {
            WriteCacheJob job;
            
            {
                std::unique_lock<std::mutex> lock(queue_mutex);
                condition.wait(lock, [this] { 
                    return !job_queue.empty() || should_terminate; 
                });
                
                if (should_terminate && job_queue.empty()) {
                    break;
                }
                
                if (!job_queue.empty()) {
                    job = std::move(job_queue.front());
                    job_queue.pop();
                }
            }
            
            // Processa il job
            if (!job.cache_file.empty()) {
                bool success = write_to_file(job.cache_file, job.data, job.offset);
                
                if (success) {
                    completed_jobs++;
                } else {
                    failed_jobs++;
                }
                
                // Chiama il callback se presente
                if (job.callback) {
                    job.callback(success);
                }
            }
            
            // Controlla se è necessaria manutenzione della cache
            auto now = std::chrono::steady_clock::now();
            if (now - last_maintenance > maintenance_interval) {
                perform_maintenance();
                last_maintenance = now;
            }
        }
    }
    
    // Scrive dati su un file
    bool write_to_file(const std::string& filename, const std::vector<byte>& data, uint64_t offset) {
        try {
            // Crea la directory se non esiste
            std::filesystem::path path(filename);
            std::filesystem::create_directories(path.parent_path());
            
            std::ofstream file;
            if (offset > 0) {
                // Apri in modalità aggiornamento
                file.open(filename, std::ios::binary | std::ios::in | std::ios::out);
                
                // Se il file non esiste, crealo
                if (!file) {
                    file.clear();
                    file.open(filename, std::ios::binary | std::ios::out);
                }
            } else {
                // Nuova scrittura
                file.open(filename, std::ios::binary | std::ios::out);
            }
            
            if (!file) {
                std::cerr << "Errore nell'apertura del file: " << filename << std::endl;
                return false;
            }
            
            // Vai all'offset specificato
            file.seekp(offset);
            
            // Scrivi i dati
            file.write(reinterpret_cast<const char*>(data.data()), data.size());
            
            if (!file) {
                std::cerr << "Errore nella scrittura del file: " << filename << std::endl;
                return false;
            }
            
            return true;
        } catch (const std::exception& e) {
            std::cerr << "Eccezione durante la scrittura del file: " << e.what() << std::endl;
            return false;
        }
    }
    
    // Esegue operazioni di manutenzione della cache
    void perform_maintenance() {
        try {
            std::cout << "Avvio manutenzione della cache..." << std::endl;
            
            // Calcola le dimensioni totali della cache
            uint64_t total_size = 0;
            std::vector<std::pair<std::filesystem::path, std::pair<uint64_t, std::filesystem::file_time_type>>> cache_files;
            
            for (const auto& entry : std::filesystem::directory_iterator(cache_directory)) {
                if (entry.is_regular_file() && entry.path().extension() == ".cache") {
                    uint64_t file_size = entry.file_size();
                    total_size += file_size;
                    cache_files.push_back({entry.path(), {file_size, entry.last_write_time()}});
                }
            }
            
            std::cout << "Dimensione totale cache: " << total_size / (1024 * 1024) << " MB" << std::endl;
            
            // Se la cache supera la dimensione massima, elimina i file meno recenti
            if (total_size > max_cache_size) {
                std::cout << "La cache supera la dimensione massima, pulizia in corso..." << std::endl;
                
                // Ordina i file per data di ultimo accesso (più vecchi prima)
                std::sort(cache_files.begin(), cache_files.end(), 
                        [](const auto& a, const auto& b) {
                            return a.second.second < b.second.second;
                        });
                
                // Elimina i file fino a tornare sotto il limite
                uint64_t freed_space = 0;
                uint64_t space_to_free = total_size - max_cache_size * 0.8;  // Libera fino all'80% della dimensione massima
                
                for (const auto& file_entry : cache_files) {
                    if (freed_space >= space_to_free) {
                        break;
                    }
                    
                    try {
                        std::cout << "Eliminazione file cache: " << file_entry.first << std::endl;
                        std::filesystem::remove(file_entry.first);
                        freed_space += file_entry.second.first;
                    } catch (const std::exception& e) {
                        std::cerr << "Errore nell'eliminazione del file: " << e.what() << std::endl;
                    }
                }
                
                std::cout << "Spazio liberato: " << freed_space / (1024 * 1024) << " MB" << std::endl;
            }
            
            std::cout << "Manutenzione della cache completata." << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "Errore durante la manutenzione della cache: " << e.what() << std::endl;
        }
    }
    
public:
    PersistenceManager(const std::string& cache_dir = "./cache") 
        : cache_directory(cache_dir), 
          last_flush(std::chrono::steady_clock::now()),
          last_maintenance(std::chrono::steady_clock::now()) {
        
        // Crea la directory di cache
        std::filesystem::create_directories(cache_directory);
        
        // Avvia il thread worker
        worker_thread = std::thread(&PersistenceManager::worker_function, this);
    }
    
    ~PersistenceManager() {
        // Attendi il completamento di tutti i job e termina il thread
        flush();
        
        should_terminate = true;
        condition.notify_one();
        
        if (worker_thread.joinable()) {
            worker_thread.join();
        }
    }
    
    // Aggiunge un job di scrittura alla coda
    void queue_write(const std::string& cache_file, const std::vector<byte>& data, uint64_t offset = 0,
                   std::function<void(bool)> callback = nullptr) {
        WriteCacheJob job;
        job.cache_file = cache_file;
        job.data = data;
        job.offset = offset;
        job.callback = callback;
        
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            job_queue.push(std::move(job));
        }
        
        condition.notify_one();
    }
    
    // Attende il completamento di tutti i job
    void flush() {
        std::unique_lock<std::mutex> lock(queue_mutex);
        if (job_queue.empty()) {
            return;
        }
        
        // Crea una promise per l'attesa
        std::promise<void> done_promise;
        std::future<void> done_future = done_promise.get_future();
        
        // Aggiunge un job speciale che completa la promise
        WriteCacheJob job;
        job.callback = [&done_promise](bool) {
            done_promise.set_value();
        };
        
        job_queue.push(std::move(job));
        lock.unlock();
        
        condition.notify_one();
        
        // Attendi il completamento
        done_future.wait();
        
        last_flush = std::chrono::steady_clock::now();
    }
    
    // Forza la manutenzione della cache
    void force_maintenance() {
        perform_maintenance();
        last_maintenance = std::chrono::steady_clock::now();
    }
    
    // Ottieni statistiche
    void get_stats(size_t& pending_jobs, size_t& completed, size_t& failed) {
        std::lock_guard<std::mutex> lock(queue_mutex);
        pending_jobs = job_queue.size();
        completed = completed_jobs.load();
        failed = failed_jobs.load();
    }
    
    // Pulisce la cache
    void clear_cache() {
        // Flush di ogni job pendente
        flush();
        
        try {
            // Elimina tutti i file di cache
            for (const auto& entry : std::filesystem::directory_iterator(cache_directory)) {
                if (entry.is_regular_file() && entry.path().extension() == ".cache") {
                    std::filesystem::remove(entry.path());
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "Errore durante la pulizia della cache: " << e.what() << std::endl;
        }
    }
};