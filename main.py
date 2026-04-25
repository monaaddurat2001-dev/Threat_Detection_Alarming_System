import sys
import os
import pandas as pd
import matplotlib.pyplot as plt  
from PyQt5 import QtWidgets, QtCore, QtGui
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas  
from PyQt5.QtWidgets import QTableWidgetItem, QGraphicsScene
from PyQt5.QtMultimedia import QSound

# Import UI definitions and custom modules
from ui_login_window import Ui_MainWindow as Ui_LoginWindow
from ui_main_window import Ui_MainWindow as Ui_FirstWindow
from ui_second_window import Ui_MainWindow as Ui_SecondWindow
from threat_engine import get_threat_evidence_summary
from visualization import simple_visualization
from interval_range import get_script_ranges


# Define the border coordinates
border_coords = [
    (41.63168, 26.4285), (41.63187, 26.42858), (41.63206, 26.42866),
    (41.63225, 26.42874), (41.63244, 26.42882), (41.63281, 26.42887),
    (41.63314, 26.42891), (41.63343, 26.42903), (41.63373, 26.42915),
    (41.63403, 26.42928), (41.63432, 26.4294), (41.63462, 26.42957),
    (41.63491, 26.42973), (41.6352, 26.4299), (41.63549, 26.43007),
    (41.63579, 26.43028), (41.63608, 26.4305), (41.63638, 26.43071),
    (41.63667, 26.43092), (41.63697, 26.4312)
]
# Load required datasets
full_data = pd.read_csv("Data/full_data.csv") 
location_df = pd.read_csv("Data/location_df.csv")

class LoginWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()

        # Load the UI for the login window
        self.ui = Ui_LoginWindow()
        self.ui.setupUi(self)

        # Set the window title
        self.setWindowTitle("Login Page")

        # Hide characters in the password input field (show dots instead)
        self.ui.lineEdit.setEchoMode(QtWidgets.QLineEdit.Password)

        # Dictionary storing user credentials and roles
        self.users = {
            "admin": {"password": "admin123", "role": "admin"},
            "operator1": {"password": "opr123", "role": "operator"},
            "operator2": {"password": "opr223", "role": "operator"},
            "operator3": {"password": "opr323", "role": "operator"},
            "operator4": {"password": "opr423", "role": "operator"}
        }

        # Connect the login button to the attempt_login function
        self.ui.pushButton.clicked.connect(self.attempt_login)

    def attempt_login(self):
        # Get username and password from the input fields
        username = self.ui.textEdit.toPlainText()
        password = self.ui.lineEdit.text()

        # Check if the username exists and the password matches
        if username in self.users and self.users[username]["password"] == password:
            # Store current user info for future use
            self.current_user = {
                "username": username,
                "role": self.users[username]["role"]
            }

            # Open the main application window and hide the login window
            self.open_main_app()
            self.hide()
        else:
            # Show error message if login fails
            QtWidgets.QMessageBox.warning(self, "Login Failed", "Invalid username or password")

    def open_main_app(self):
        # Open the main application window and pass current user data
        self.main_app = MainApp(self.current_user)
        self.main_app.show()

class SecondWindow(QtWidgets.QMainWindow):
    def __init__(self, first_window, user_info):
        super().__init__()
        self.ui = Ui_SecondWindow()
        self.ui.setupUi(self)
        self.first_window = first_window  # Reference to the login window
        self.user_info = user_info        # Dictionary with user information

        # Set window title with logged-in username
        self.setWindowTitle(f"Threat Analysis Viewer - {self.user_info['username']}")
        self.resize(800, 600)

        # Initialize UI components and logic
        self.setup_plot_widget()
        self.setup_connections()
        self.setup_initial_state()

    def setup_plot_widget(self):
        """Initialize and configure the matplotlib plot widget"""
        self.figure, self.ax = plt.subplots(figsize=(6, 4))  # Create figure and axes

        # Set background colors for the figure and plot area
        self.figure.set_facecolor('#ffffff')
        self.ax.set_facecolor('#f8f9fa')

        # Enable grid with dotted lines
        self.ax.grid(True, linestyle=':', alpha=0.7)

        # Create canvas to display matplotlib plot
        self.canvas = FigureCanvas(self.figure)
        self.canvas.setSizePolicy(
            QtWidgets.QSizePolicy.Expanding,
            QtWidgets.QSizePolicy.Expanding
        )

        # Remove any existing widget in the layout and add the canvas
        if self.ui.verticalLayout.count():
            self.ui.verticalLayout.itemAt(0).widget().setParent(None)
        self.ui.verticalLayout.addWidget(self.canvas)

        # Set layout margins and spacing
        self.ui.verticalLayout.setContentsMargins(5, 5, 5, 5)
        self.ui.verticalLayout.setSpacing(5)

    def setup_connections(self):
        """Connect all UI signals to their respective handlers"""
        self.ui.commandLinkButton.clicked.connect(self.return_to_first)  # Return button
        self.ui.pushButton.clicked.connect(self.run_analysis)            # Run analysis button

    def setup_initial_state(self):
        """Initialize the spin boxes and show an empty plot"""
        self.ui.spinBoxint1.setRange(1, 9999)
        self.ui.spinBoxint2.setRange(1, 9999)
        self.ui.spinBoxint1.setValue(1)
        self.ui.spinBoxint2.setValue(5)

        # Show a blank plot at start
        self.show_initial_plot()

    def show_initial_plot(self):
        """Display a blank plot with no axes or data"""
        self.ax.clear()
        self.ax.set_xticks([])
        self.ax.set_yticks([])
        self.ax.grid(False)
        self.figure.tight_layout()
        self.canvas.draw()

    def return_to_first(self):
        """Return to the main window and hide this one"""
        self.hide()
        self.first_window.show()

    def run_analysis(self):
        """Run the threat analysis based on user inputs and update the plot and list"""
        try:
            # Retrieve inputs from the UI
            weather = self.ui.comboBoxW.currentText()
            time_of_day = self.ui.comboBoxToD.currentText()
            from_interval = self.ui.spinBoxint1.value()
            to_interval = self.ui.spinBoxint2.value()

            # Ensure interval range is valid
            if from_interval > to_interval:
                QtWidgets.QMessageBox.warning(
                    self, "Invalid Range", "From interval must be less than To interval"
                )
                return

            # Clear old results from the list
            self.ui.listWidget.clear()

            # Prepare for collecting analysis results
            interval_ids = range(from_interval, to_interval + 1)
            alarm_values = []
            valid_intervals = []

            for interval_id in interval_ids:
                # Get threat analysis summary for each interval
                summary = get_threat_evidence_summary(time_of_day, weather, interval_id)

                # Extract scaled probabilities (if any)
                probs = [p['scaled_joint'] for p in summary['detailed_probabilities']] \
                        if summary['detailed_probabilities'] else []

                # If no threats detected, show message
                if not probs:
                    item = QtWidgets.QListWidgetItem(f"Interval {interval_id}: No threats detected")
                    self.ui.listWidget.addItem(item)
                    continue

                # Collect data for plotting
                alarm_values.append(max(probs))  # Could also use avg or all values
                valid_intervals.append(interval_id)

                # Display each threat probability in the list
                for i, prob in enumerate(probs, 1):
                    item_text = f"Interval {interval_id} - Threat {i}: {prob:.4f}"
                    if prob > 0.5:  # Highlight high-risk items
                        item = QtWidgets.QListWidgetItem(item_text + " (ALARM)")
                        item.setForeground(QtGui.QColor(220, 53, 69))  # Red text
                    else:
                        item = QtWidgets.QListWidgetItem(item_text)
                    self.ui.listWidget.addItem(item)

            # Update the plot with results, or reset if none valid
            if valid_intervals:
                self.plot_results(valid_intervals, alarm_values, weather, time_of_day)
            else:
                self.show_initial_plot()

        except Exception as e:
            # Show an error if the analysis fails
            QtWidgets.QMessageBox.critical(
                self, "Analysis Error", f"Failed to run analysis:\n{str(e)}"
            )

    def plot_results(self, intervals, values, weather, time_of_day):
        """Render the alarm values as a line chart"""
        self.ax.clear()

        # Define plot and threshold line colors
        line_color = '#0d6efd'     # Blue
        threshold_color = '#dc3545'  # Red

        # Plot the alarm values
        self.ax.plot(
            intervals, values,
            marker='o', markersize=6,
            linestyle='-', linewidth=1.5,
            color=line_color, label='Alarm Score'
        )

        # Plot threshold line at 0.5
        self.ax.axhline(
            y=0.5, color=threshold_color,
            linestyle='--', linewidth=1.25,
            label='Alarm Threshold'
        )

        # Set titles and labels
        self.ax.set_title(
            f'Threat Analysis: {weather}, {time_of_day}',
            fontsize=9, pad=9
        )
        self.ax.set_xlabel('Interval ID', fontsize=8)
        self.ax.set_ylabel('Scaled Alarm Value', fontsize=8)
        self.ax.set_xticks(intervals)
        self.ax.tick_params(axis='both', labelsize=8)

        # Add grid and legend
        self.ax.grid(True, linestyle=':', alpha=0.7)
        self.ax.legend(loc='lower right', fontsize=5, framealpha=0.7, facecolor='white')

        # Adjust layout and render the updated plot
        self.figure.tight_layout()
        self.canvas.draw()

    def resizeEvent(self, event):
        """Ensure the plot resizes smoothly with the window"""
        super().resizeEvent(event)
        if hasattr(self, 'canvas'):
            self.figure.tight_layout()
            self.canvas.draw()

class MainApp(QtWidgets.QMainWindow):
    def __init__(self, user_info):  # Accept user_info parameter for user authentication
        super(MainApp, self).__init__()
        self.user_info = user_info  # Store the user info (like role and username)
        self.ui = Ui_FirstWindow()  # Initialize the UI for the first window
        self.ui.setupUi(self)  # Set up the UI

        # Hide the button for non-admin users
        if self.user_info['role'] != 'admin':  
            self.ui.commandLinkButton.setVisible(False)  # Hide the command link button if not admin

        # Set window title with username and role
        self.setWindowTitle(f"Threat Analysis System - {self.user_info['username']} ({self.user_info['role']})")
     
        self.second_window = None  # Initialize second window as None
        self.ui.commandLinkButton.clicked.connect(self.open_second_window)  # Connect the button to open second window

        # Initialize components for script selection, spin box, alarm sound, and graphics view
        self.script_ranges = get_script_ranges(location_df)
        self.setup_script_combo_box()
        self.setup_spin_box()
        self.setup_alarm_sound()
        self.clear_graphics_view()

        # Real-time visualization controls
        self.visualization_timer = QtCore.QTimer()  # Set up timer for real-time updates
        self.current_interval = 0  # Set initial interval
        self.is_playing = False  # Set playback state
        self.playback_speed = 500  # Set the playback speed (ms between updates)

        # Connect buttons to their respective actions
        self.ui.pushButton.clicked.connect(self.run_inference)
        self.ui.comboBox_1.currentTextChanged.connect(self.update_interval_range)

        # Connect real-time control buttons
        self.ui.startButton.clicked.connect(self.start_real_time)
        self.ui.pauseButton.clicked.connect(self.toggle_pause)
        self.ui.stopButton.clicked.connect(self.stop_real_time)
        self.ui.stopButton.setEnabled(False)  # Disable the stop button initially
        self.visualization_timer.timeout.connect(self.update_real_time)

    def open_second_window(self):
        # Check if the user is admin before opening the second window
        if self.user_info['role'] == 'admin':  
            # Close the existing window if one exists
            if self.second_window:
                self.second_window.close()
            # Open new second window
            self.second_window = SecondWindow(self, self.user_info)
            self.second_window.show()
            self.hide()  # Hide the main window while the second window is open
    
    def closeEvent(self, event):
        # Close second window when main window is closed
        if self.second_window:
            self.second_window.close()
        event.accept()

    def setup_script_combo_box(self):
        self.ui.comboBox_1.clear()  # Clear the combo box before adding items
        for script in sorted(self.script_ranges.keys()):  # Sort and add script options
            min_i, max_i = self.script_ranges[script]  # Get the valid interval for each script
            self.ui.comboBox_1.addItem(script)  # Add script name to combo box
            idx = self.ui.comboBox_1.findText(script)  # Find index of the script
            # Add tooltip for valid interval range
            self.ui.comboBox_1.setItemData(
                idx,
                f"Valid intervals: {min_i} to {max_i}",
                QtCore.Qt.ToolTipRole
            )

    def setup_spin_box(self):
        self.ui.spinBox.setMaximum(9999)  # Set maximum value for spin box
        self.ui.spinBox.setMinimum(1)  # Set minimum value for spin box

    def setup_alarm_sound(self):
        sound_file = "Sounds/beep.wav"  # Define the path to the alarm sound file
        possible_paths = [
            os.path.join(os.path.dirname(__file__), sound_file),
            os.path.join("sounds", sound_file),
            sound_file
        ]
        
        # Check each possible path for the sound file
        for path in possible_paths:
            if os.path.exists(path):  # If file exists, load the sound
                self.alarm_sound = QSound(path)
                break
        else:
            print(f"Warning: Could not find sound file '{sound_file}'")  # Warn if sound file is not found

    def clear_graphics_view(self):
        scene = QGraphicsScene()  # Create a new empty scene
        self.ui.graphicsView.setScene(scene)  # Set this empty scene in the graphics view

    def update_interval_range(self, script):
        # Update the spin box range based on the selected script
        if script in self.script_ranges:
            min_i, max_i = self.script_ranges[script]
            self.ui.spinBox.setMinimum(min_i)  # Set minimum interval
            self.ui.spinBox.setMaximum(max_i)  # Set maximum interval
            self.ui.spinBox.setValue(min_i)  # Set default value to the minimum interval
            self.statusBar().showMessage(f"Valid intervals for {script}: {min_i} to {max_i}")

    def start_real_time(self):
        script = self.ui.comboBox_1.currentText()  # Get selected script
        if script == "Select script":  # Ensure a script is selected
            QtWidgets.QMessageBox.warning(self, "Warning", "Please select a script first!")
            return
        
        min_i, max_i = self.script_ranges.get(script, (0, 0))  # Get script's valid interval range
        self.current_interval = min_i  # Set current interval to the minimum value
        self.max_interval = max_i  # Set the maximum interval
        self.is_playing = True  # Set playback state to playing
        
        # Disable UI controls during real-time playback
        self.ui.pushButton.setEnabled(False)
        self.ui.spinBox.setEnabled(False)
        self.ui.startButton.setEnabled(False)
        self.ui.pauseButton.setEnabled(True)
        self.ui.stopButton.setEnabled(True)
        
        self.visualization_timer.start(self.playback_speed)  # Start the timer for real-time updates

    def stop_real_time(self):
        self.visualization_timer.stop()  # Stop the visualization timer
        self.is_playing = False  # Set playback state to stopped
        
        # Enable UI controls after stopping real-time playback
        self.ui.pushButton.setEnabled(True)
        self.ui.spinBox.setEnabled(True)
        self.ui.startButton.setEnabled(True)
        self.ui.pauseButton.setEnabled(False)
        self.ui.stopButton.setEnabled(False)
        self.ui.pauseButton.setText("Pause")  # Reset pause button text
        
        self.statusBar().showMessage("Playback stopped")  # Update status bar

    def toggle_pause(self):
        # Toggle between pause and resume states
        if self.is_playing:
            self.visualization_timer.stop()  # Pause the timer
            self.is_playing = False
            self.ui.pauseButton.setText("Resume")  # Change button text to 'Resume'
            self.statusBar().showMessage("Playback paused")  # Update status bar
        else:
            self.visualization_timer.start(self.playback_speed)  # Resume the timer
            self.is_playing = True
            self.ui.pauseButton.setText("Pause")  # Change button text to 'Pause'
            self.statusBar().showMessage(f"Playing interval {self.current_interval}/{self.max_interval}")  # Update status bar

    def update_real_time(self):
        # Update the current interval during real-time playback
        if self.current_interval > self.max_interval:  # Stop if the current interval exceeds the max
            self.stop_real_time()
            self.statusBar().showMessage("Playback completed")
            return
        
        self.ui.spinBox.setValue(self.current_interval)  # Update the spin box with the current interval
        self.run_inference()  # Run inference for the current interval
        self.current_interval += 1  # Increment the interval
        self.statusBar().showMessage(f"Playing interval {self.current_interval}/{self.max_interval}")  # Update status bar

    def run_inference(self):
        script = self.ui.comboBox_1.currentText()  # Get selected script
        interval = self.ui.spinBox.value()  # Get selected interval
        weather = self.ui.comboBox_2.currentText()  # Get selected weather condition
        time_of_day = self.ui.comboBox_3.currentText()  # Get selected time of day

        if not self.is_playing:  # If not in playback mode, validate the interval
            min_i, max_i = self.script_ranges.get(script, (0, 0))
            if interval < min_i or interval > max_i:  # If interval is invalid
                QtWidgets.QMessageBox.warning(
                    self, "Invalid Interval",
                    f"Interval {interval} is invalid for {script}.\n"
                    f"Please enter a value between {min_i} and {max_i}."
                )
                return

        assessment = get_threat_evidence_summary(time_of_day, weather, interval)  # Run the assessment for threat detection
    
        if 'error' in assessment:  # Handle errors from the assessment
            QtWidgets.QMessageBox.warning(self, "Error", assessment['error'])
            return

        self.update_table(assessment)  # Update the table with assessment results
        self.update_visualization(script, interval)  # Update the visualization for the current interval
    
        # Check if any alarm was raised and play the alarm sound if so
        if any("Alarm raised" in status for status in assessment.get('alarm_statuses', [])):
            if hasattr(self, 'alarm_sound') and self.alarm_sound:
                self.alarm_sound.play()

    def update_table(self, assessment):
        # Update the table with alarm status, event types, and probabilities
        alarm_statuses = assessment.get('alarm_statuses', [])
        detailed_probs = assessment.get('detailed_probabilities', [])
    
        headers = ['Alarm Status', 'Alarm Value', 'Position', 'Event Type']

        self.ui.tableWidget.setRowCount(len(alarm_statuses))  # Set the row count
        self.ui.tableWidget.setColumnCount(len(headers))  # Set the column count
        self.ui.tableWidget.setHorizontalHeaderLabels(headers)  # Set the header labels

        prob_map = {(prob['event_type'], prob['position']): prob['scaled_joint'] 
                    for prob in detailed_probs}

        for row, status_text in enumerate(alarm_statuses):  # Fill the table with data
            if ' → ' in status_text:
                event_part, alarm_status = status_text.split(' → ')
                event_type = event_part.replace('Event: ', '').split(' (')[0]
                position = event_part.split(' (')[1].rstrip(')')
            
                scaled_prob = prob_map.get((event_type, position), "N/A")
                prob_text = f"{scaled_prob:.4f}" if isinstance(scaled_prob, (int, float)) else scaled_prob
            
                items = [alarm_status, prob_text, position, event_type]
            
                for col, value in enumerate(items):
                    item = QTableWidgetItem(str(value))
                    if alarm_status == "Alarm raised":  # Highlight alarm rows
                        item.setBackground(QtGui.QColor(255, 200, 200))
                        item.setForeground(QtGui.QColor(255, 0, 0))
                    self.ui.tableWidget.setItem(row, col, item)

        self.ui.tableWidget.resizeColumnsToContents()  # Resize columns to fit content

    def update_visualization(self, script_name, interval_id):
        # Clear the current graphics view and set new scene for visualization
        self.clear_graphics_view()
        
        scene = simple_visualization(
            script_name=script_name,
            interval_id=interval_id,
            data=full_data,
            border_coords=border_coords,
            location_df=location_df,
            static_file_path="BorderData/mygepdata.xlsx"
        )
        
        if scene:
            self.ui.graphicsView.setScene(scene)  # Set the scene in the graphics view
            self.ui.graphicsView.fitInView(scene.sceneRect())  # Fit the view to the scene

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)

    # Show login window first before main application window
    login_window = LoginWindow()
    login_window.show()
    
    sys.exit(app.exec_())  # Start the application event loop
