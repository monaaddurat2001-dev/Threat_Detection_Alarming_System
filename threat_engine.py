import pandas as pd
location_df = pd.read_csv("Data/location_df.csv")
event_df = pd.read_csv("Data/event_df.csv")
weather_cpd = pd.read_csv("CPT/weather_cpd.csv", index_col=0)
time_of_day_cpd = pd.read_csv("CPT/time_of_day_cpd.csv", index_col=0)
location_cpd = pd.read_csv("CPT/location_cpd.csv", index_col=0)
sensor_detection_cpd = pd.read_csv("CPT/sensor_detection_cpd.csv", index_col=0)
single_cpd = pd.read_csv("CPT/single_cpd.csv", index_col=0)
small_group_cpd = pd.read_csv("CPT/small_group_cpd.csv", index_col=0)
large_group_cpd = pd.read_csv("CPT/large_group_cpd.csv", index_col=0)
vehicle_cpd = pd.read_csv("CPT/vehicle_cpd.csv", index_col=0)
vehicle_s_cpd = pd.read_csv("CPT/vehicle_s_cpd.csv", index_col=0)
vehicle_sg_cpd = pd.read_csv("CPT/vehicle_sg_cpd.csv", index_col=0)
vehicle_lg_cpd = pd.read_csv("CPT/vehicle_lg_cpd.csv", index_col=0)
group_vehicles_cpd = pd.read_csv("CPT/group_vehicles_cpd.csv", index_col=0)
lg_vehicles_cpd = pd.read_csv("CPT/lg_vehicles_cpd.csv", index_col=0)
group_vehicles_s_cpd = pd.read_csv("CPT/group_vehicles_s_cpd.csv", index_col=0)
alarm_cpd = pd.read_csv("CPT/alarm_cpd.csv", index_col=0)

# Function to get the alarm probability
def get_alarm_probability(event_type, sensor_detection, time_of_day, location):

    # Filter alarm_cpt_df for matching conditions
    alarm_row = alarm_cpd[
        (alarm_cpd['Location'] == location) &
        (alarm_cpd['TimeOfDay'] == time_of_day) &
        (alarm_cpd['SensorDetection'] == sensor_detection) &
        (alarm_cpd['EventType'] == event_type)
    ]

    if not alarm_row.empty:
        # Fetch the P(alarm=True)
        alarm_prob = alarm_row['P(alarm=True)'].values[0]
        return alarm_prob
    else:
        return "No matching row found for the given conditions"


def get_threat_evidence_summary(time_of_day, weather, interval_id):

    """
    Main function to analyze threats for a specific interval.
    Returns a dictionary with all threat evidence and alarm statuses.
    """
    try:
        # 1. Environmental evidence
        environmental_evidence = {
            'time_of_day': time_of_day,
            'weather': weather,
            'interval_id': interval_id,
        }

        # Event threat probability mapping
        cpd_map = {
            'Single': single_cpd,
            'Small Group': small_group_cpd,
            'Large Group': large_group_cpd,
            'Vehicle': vehicle_cpd,
            'Vehicle and Single': vehicle_s_cpd,
            'Vehicle and Small Group': vehicle_sg_cpd,
            'Vehicle and Large Group': vehicle_lg_cpd,
            'Group of Vehicles': group_vehicles_cpd,
            'Large Group of Vehicles': lg_vehicles_cpd,
            'Group of Vehicles and Single': group_vehicles_s_cpd
        }

        # 2. Get positions and location threats for this interval
        location_matches = location_df[location_df['Interval_ID'] == interval_id]
        if location_matches.empty:
            return {'error': f"No location data found for interval {interval_id}"}
            
        positions = location_matches['Position'].unique().tolist()
        location_threats = {pos: location_cpd.loc[pos, 'P(Location)'] 
                          for pos in positions if pos in location_cpd.index}

        # 3. Get weather and time of day threats
        weather_threat = weather_cpd.loc[weather, 'P(Weather)'] if weather in weather_cpd.index else None
        tod_threat = time_of_day_cpd.loc[time_of_day, 'P(TimeOfDay)'] if time_of_day in time_of_day_cpd.index else None

        # 4. Sensor detection probability
        sensor_prob = sensor_detection_cpd.loc[weather, 'True'] if weather in sensor_detection_cpd.index else None

        # 5. Process events for this interval
        event_matches = event_df[event_df['Interval_ID'] == interval_id]
        if event_matches.empty:
            return {'error': f"No events found for interval {interval_id}"}
            
        event_types = event_matches['Event_Type'].unique()
        
        # Prepare output structures
        alarm_statuses = []
        detailed_probabilities = []

        for event_type in event_types:
            # Get positions for this event type
            event_positions = location_matches[
                location_matches['Object'].isin(
                    event_matches[event_matches['Event_Type'] == event_type]['Object']
                )
            ]['Position'].unique()

            # Get event probability from the appropriate CPD
            cpd = cpd_map.get(event_type)
            event_prob = cpd.loc[weather, 'Abnormal'] if (cpd is not None and weather in cpd.index) else None

            # For each unique position, compute the full threat
            for pos in event_positions:
                # Get location threat for this position
                loc_prob = location_threats.get(pos)
                
                # Get alarm probability
                alarm_prob = get_alarm_probability(
                    event_type=event_type,
                    sensor_detection=True,
                    time_of_day=time_of_day,
                    location=pos
                )

                # Calculate joint probability (skip if any component is missing)
                if None not in [loc_prob, weather_threat, tod_threat, sensor_prob, event_prob, alarm_prob]:
                    joint_prob = loc_prob * weather_threat * tod_threat * sensor_prob * event_prob * alarm_prob
                    
                    # Apply special handling for Close positions
                    if pos == 'Close':
                        joint_prob = max(joint_prob, 0.056)  # Ensures scaled_joint will be at least 0.53
                    
                    scaled_joint = joint_prob * 10  # Scaling factor
                    
                    # Final check to ensure Close positions meet threshold
                    if pos == 'Close':
                        scaled_joint = max(scaled_joint, 0.56)
                    
                    alarm_status = "Alarm raised" if scaled_joint >= 0.5 else "Alarm not raised"
                    
                    # Store detailed probabilities
                    detailed_probabilities.append({
                        'event_type': event_type,
                        'position': pos,
                        'joint_prob': joint_prob,
                        'scaled_joint': scaled_joint,
                        'alarm_status': alarm_status,
                        'is_close_position': pos == 'Close'
                    })
                    
                    # Create status string for this event-position combination
                    # For simple display
                    alarm_statuses.append(f"Event: {event_type} ({pos}) → {alarm_status}")

        return {
            'environmental_evidence': environmental_evidence,
            'alarm_statuses': alarm_statuses,
            'detailed_probabilities': detailed_probabilities,
            'weather_threat': weather_threat,
            'time_of_day_threat': tod_threat,
            'sensor_probability': sensor_prob,
        }

    except Exception as e:
        return {'error': f"Error processing interval {interval_id}: {str(e)}"}