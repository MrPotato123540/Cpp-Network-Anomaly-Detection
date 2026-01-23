#include <iostream>
#include <string>
#include <memory>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <algorithm>

// Project Headers
#include "PacketReceiver.h"
#include "FlowManager.h"
#include "KMeansStrategy.h"
#include "ZScoreStrategy.h"
#include "ConsoleAnomalyLogger.h"
#include "FileAnomaly.h"
#include "WhitelistEvaluator.h"
#include "IPacketSource.h"
#include "PcapFileSource.h"
#include "LiveNetworkSource.h"
#include "IAnomalyListener.h"

// ImGui & GLFW Headers
#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include <GLFW/glfw3.h>

// ---------------------------------------------------------
// 1. DATA STRUCTURES & LISTENER CLASS
// ---------------------------------------------------------

// Struct to store log details for the GUI table
struct LogEntry {
    std::string type;   // "ANOMALY" or "SAFE(FP)"
    std::string srcIP;
    std::string dstIP;
    double score;
    float color[4];     // RGBA color code for text
};

class GuiAnomalyListener : public IAnomalyListener {
private:
    std::vector<LogEntry> logs;      // Stores log rows for the table
    std::vector<float> scoreHistory; // Stores anomaly scores for the graph
    
    std::mutex mtx;                  // Mutex to ensure thread-safety between Backend and GUI
    
    const size_t MAX_LOGS = 1000;    // Limit log size to prevent high memory usage
    const size_t MAX_HISTORY = 200;  // Maximum data points for the graph (X-axis)

public:
    // Called by the backend thread when an anomaly is found
    void onAnomalyDetected(const FlowKey& /*key*/, double score, const std::string& srcIP, const std::string& dstIP) override {
        std::lock_guard<std::mutex> lock(mtx); // Lock mutex to protect shared data
        
        // Add to table logs (Red color for danger)
        logs.push_back({ "ANOMALY", srcIP, dstIP, score, {1.0f, 0.0f, 0.0f, 1.0f} });
        if (logs.size() > MAX_LOGS) logs.erase(logs.begin()); // Remove oldest if full

        // Add to graph history
        scoreHistory.push_back((float)score);
        if (scoreHistory.size() > MAX_HISTORY) scoreHistory.erase(scoreHistory.begin());
    }

    // Called when an anomaly matches the whitelist (False Positive)
    void onFalsePositiveDetected(const FlowKey& /*key*/, double score, const std::string& srcIP, const std::string& dstIP) override {
        std::lock_guard<std::mutex> lock(mtx);
        
        // Add to table logs (Green color for safe)
        logs.push_back({ "SAFE (FP)", srcIP, dstIP, score, {0.0f, 1.0f, 0.0f, 1.0f} });
        if (logs.size() > MAX_LOGS) logs.erase(logs.begin());

        // We still add it to graph to show activity, but maybe it's low score
        scoreHistory.push_back((float)score);
        if (scoreHistory.size() > MAX_HISTORY) scoreHistory.erase(scoreHistory.begin());
    }

    // Returns a copy of logs for the GUI thread to render
    std::vector<LogEntry> getLogsSnapshot() {
        std::lock_guard<std::mutex> lock(mtx);
        return logs; 
    }

    // Returns a copy of score history for the plot
    std::vector<float> getScoreHistory() {
        std::lock_guard<std::mutex> lock(mtx);
        return scoreHistory;
    }
    
    // Clears all data from the UI
    void clearLogs() {
        std::lock_guard<std::mutex> lock(mtx);
        logs.clear();
        scoreHistory.clear();
    }
};

// ---------------------------------------------------------
// GLOBAL VARIABLES
// ---------------------------------------------------------
IPacketSource* globalSourcePtr = nullptr; // Pointer for signal handling and cleanup

// GLFW Error Callback
static void glfw_error_callback(int error, const char* description) {
    fprintf(stderr, "GLFW Error %d: %s\n", error, description);
}

// ---------------------------------------------------------
// MAIN APPLICATION
// ---------------------------------------------------------
int main(int argc, char* argv[]) {
    // Check arguments
    if (argc < 4) {
        std::cout << "\nUSAGE: " << argv[0] << " <MODE> <INPUT> <MODEL> [ALGO]\n";
        std::cout << "MODES: train, detect, live\n";
        std::cout << "EXAMPLE: " << argv[0] << " live eth0 model.json kmeans\n";
        return 1;
    }

    std::string mode = argv[1];
    std::string input = argv[2];
    std::string modelFile = argv[3];
    std::string algo = (argc > 4) ? argv[4] : "kmeans";

    // -----------------------------------------------------
    // 1. Setup Window & ImGui
    // -----------------------------------------------------
    glfwSetErrorCallback(glfw_error_callback);
    if (!glfwInit()) return 1;

    // GL 3.0 + GLSL 130 (Compatible with most Linux systems)
    const char* glsl_version = "#version 130";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);

    // Create window with graphics context
    GLFWwindow* window = glfwCreateWindow(1280, 720, "Anomaly Detection Monitor", NULL, NULL);
    if (window == NULL) return 1;
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1); // Enable V-Sync

    // Setup ImGui context
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    ImGui::StyleColorsDark(); // Dark theme

    // Setup Platform/Renderer backends
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    // -----------------------------------------------------
    // 2. Setup Backend Logic
    // -----------------------------------------------------
    std::unique_ptr<FlowManager> flowManager;
    std::unique_ptr<IDetectionStrategy> strategy;
    std::unique_ptr<IPacketSource> source;
    std::unique_ptr<PacketReceiver> receiver;
    std::unique_ptr<GuiAnomalyListener> guiListener;
    std::unique_ptr<WhitelistEvaluator> whitelistEval;
    
    std::thread backendThread; // To run detection in background

    try {
        flowManager = std::make_unique<FlowManager>();

        // Choose Algorithm
        if (algo == "zscore") strategy = std::make_unique<ZScoreStrategy>(3.5);
        else strategy = std::make_unique<KMeansStrategy>(5, 100);

        // Choose Source
        if (mode == "live") source = std::make_unique<LiveNetworkSource>(input);
        else source = std::make_unique<PcapFileSource>(input);

        globalSourcePtr = source.get(); 

        receiver = std::make_unique<PacketReceiver>(*source, *flowManager, *strategy);

        // Create and attach GUI Listener
        guiListener = std::make_unique<GuiAnomalyListener>();
        receiver->addListener(guiListener.get());

        // Load Whitelist if not training
        whitelistEval = std::make_unique<WhitelistEvaluator>();
        if (mode != "train") {
            whitelistEval->loadWhitelist("trusted_ips.txt");
            receiver->setEvaluator(whitelistEval.get());
        }

        // Add File Logger (Logs to disk)
        static FileAnomalyLogger fileLogger("detected_anomalies.log");
        receiver->addListener(&fileLogger);

        // -------------------------------------------------
        // 3. Start Backend Thread
        // -------------------------------------------------
        std::cout << "[INFO] Starting Backend Thread...\n";
        backendThread = std::thread([&]() {
            if (mode == "train") {
                receiver->runTrainingMode(modelFile);
            } else {
                receiver->runDetectMode(modelFile);
            }
        });

    } catch (const std::exception& e) {
        std::cerr << "Initialization Error: " << e.what() << std::endl;
        return 1;
    }

    // -----------------------------------------------------
    // 4. Main GUI Loop
    // -----------------------------------------------------
    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        // Start the ImGui frame
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        // --- DASHBOARD UI ---
        
        // Fullscreen viewport setup
        const ImGuiViewport* viewport = ImGui::GetMainViewport();
        ImGui::SetNextWindowPos(viewport->WorkPos);
        ImGui::SetNextWindowSize(viewport->WorkSize);

        ImGui::Begin("Dashboard", nullptr, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize);

        // Header Info
        ImGui::Text("Mode: %s | Algorithm: %s | Input: %s", mode.c_str(), algo.c_str(), input.c_str());
        ImGui::Separator();

        // --- GRAPH SECTION ---
        ImGui::Text("Live Anomaly Score Trend");
        
        // Get fresh data from listener
        std::vector<float> scores = guiListener->getScoreHistory();
        
        if (!scores.empty()) {
            // PlotLines: (Label, Data, Count, Offset, OverlayText, ScaleMin, ScaleMax, GraphSize)
            // ScaleMax is set to 20.0f, adjust this if your Z-Score/KMeans outputs larger numbers.
            ImGui::PlotLines("##ScoreGraph", scores.data(), (int)scores.size(), 0, 
                             "Anomaly Score", 0.0f, 20.0f, ImVec2(ImGui::GetContentRegionAvail().x, 100));
        } else {
            ImGui::TextColored(ImVec4(0.5, 0.5, 0.5, 1), "Waiting for traffic data...");
        }
        ImGui::Separator();

        // --- TABLE SECTION ---
        ImGui::Text("Detected Anomalies (Live Flow)");
        
        // Table Flags: Scrollable, Resizable, Borders
        static ImGuiTableFlags flags = ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersV | ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable;

        if (ImGui::BeginTable("LogTable", 4, flags)) {
            // Setup Columns
            ImGui::TableSetupScrollFreeze(0, 1); // Freeze header
            ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 100.0f);
            ImGui::TableSetupColumn("Source IP");
            ImGui::TableSetupColumn("Destination IP");
            ImGui::TableSetupColumn("Anomaly Score");
            ImGui::TableHeadersRow();

            // Get log data
            std::vector<LogEntry> logs = guiListener->getLogsSnapshot();

            // Loop reversed to show newest logs at top
            for (auto it = logs.rbegin(); it != logs.rend(); ++it) {
                ImGui::TableNextRow();
                
                ImGui::TableSetColumnIndex(0);
                ImGui::TextColored(ImVec4(it->color[0], it->color[1], it->color[2], it->color[3]), "%s", it->type.c_str());

                ImGui::TableSetColumnIndex(1);
                ImGui::Text("%s", it->srcIP.c_str());

                ImGui::TableSetColumnIndex(2);
                ImGui::Text("%s", it->dstIP.c_str());

                ImGui::TableSetColumnIndex(3);
                ImGui::Text("%.4f", it->score);
            }
            ImGui::EndTable();
        }
        
        // Clear Button
        if (ImGui::Button("Clear Logs")) {
            guiListener->clearLogs();
        }

        ImGui::End(); // End Dashboard

        // Rendering
        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.15f, 0.15f, 0.15f, 1.00f); // Dark gray background
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(window);
    }

    // -----------------------------------------------------
    // 5. Cleanup Resources
    // -----------------------------------------------------
    
    // Stop packet capture
    if (globalSourcePtr) {
        std::cout << "[INFO] Stopping Packet Capture...\n";
        globalSourcePtr->close();
    }

    // Wait for backend thread to finish
    if (backendThread.joinable()) {
        backendThread.join();
        std::cout << "[INFO] Backend Thread Joined.\n";
    }

    // Shutdown GUI
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}
