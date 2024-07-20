from burp import IBurpExtender, ITab, IHttpListener, IMessageEditorController
from javax.swing import JPanel, JButton, JTable, JScrollPane, JSplitPane, JTabbedPane
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout

class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        
        # Set our extension name
        callbacks.setExtensionName("HTTP Monitor")
        
        # Create the main tab UI
        self.panel = JPanel(BorderLayout())
        self.splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self.panel.add(self.splitPane, BorderLayout.CENTER)
        
        # Create the top panel with the monitor button
        self.topPanel = JPanel()
        self.monitorButton = JButton("Start Monitoring", actionPerformed=self.toggleMonitoring)
        self.topPanel.add(self.monitorButton)
        self.panel.add(self.topPanel, BorderLayout.NORTH)
        
        # Create the table to show HTTP history
        self.tableModel = DefaultTableModel(["Method", "URL", "Status", "Length", "MIME Type"], 0)
        self.table = JTable(self.tableModel)
        self.table.getSelectionModel().addListSelectionListener(self.onTableRowSelection)
        self.scrollPane = JScrollPane(self.table)
        self.splitPane.setTopComponent(self.scrollPane)
        
        # Create the horizontal split pane for request/response viewers
        self.reqRespSplitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        
        # Create tabs for request viewer
        self.requestTabs = JTabbedPane()
        self.requestViewer = callbacks.createMessageEditor(self, False)
        self.requestTabs.addTab("Request", self.requestViewer.getComponent())
        
        # Create tabs for response viewer
        self.responseTabs = JTabbedPane()
        self.responseViewer = callbacks.createMessageEditor(self, False)
        self.responseTabs.addTab("Response", self.responseViewer.getComponent())
        
        # Add request and response tabs to the split pane
        self.reqRespSplitPane.setLeftComponent(self.requestTabs)
        self.reqRespSplitPane.setRightComponent(self.responseTabs)
        self.splitPane.setBottomComponent(self.reqRespSplitPane)
        
        # Add the custom tab to Burp Suite
        callbacks.addSuiteTab(self)
        
        # Initialize monitoring state and store for HTTP messages
        self.monitoring = False
        self.messages = []

    def toggleMonitoring(self, event):
        self.monitoring = not self.monitoring
        self.monitorButton.setText("Stop Monitoring" if self.monitoring else "Start Monitoring")
        
        if self.monitoring:
            self.callbacks.registerHttpListener(self)
        else:
            self.callbacks.removeHttpListener(self)
    
    def getTabCaption(self):
        return "HTTP Monitor"
    
    def getUiComponent(self):
        return self.panel
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if self.monitoring and not messageIsRequest:
            requestInfo = self.helpers.analyzeRequest(messageInfo)
            responseInfo = self.helpers.analyzeResponse(messageInfo.getResponse())
            
            method = requestInfo.getMethod()
            url = requestInfo.getUrl().toString()
            status = responseInfo.getStatusCode()
            length = len(messageInfo.getResponse())
            mimeType = responseInfo.getStatedMimeType()
            
            row = [method, url, status, length, mimeType]
            self.messages.append(messageInfo)
            self.tableModel.addRow(row)
    
    def onTableRowSelection(self, event):
        if not event.getValueIsAdjusting() and self.table.getSelectedRow() != -1:
            row = self.table.getSelectedRow()
            self.currentRequestResponse = self.messages[row]
            request = self.currentRequestResponse.getRequest()
            response = self.currentRequestResponse.getResponse()
            self.requestViewer.setMessage(request, True)
            self.responseViewer.setMessage(response, False)
    
    def getHttpService(self):
        return self.currentRequestResponse.getHttpService() if self.currentRequestResponse else None
    
    def getRequest(self):
        return self.currentRequestResponse.getRequest() if self.currentRequestResponse else None
    
    def getResponse(self):
        return self.currentRequestResponse.getResponse() if self.currentRequestResponse else None

# To run this script, ensure Jython is configured in Burp Suite, then load this script in the Extender tab.
