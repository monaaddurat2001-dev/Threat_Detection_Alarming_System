import pandas as pd
from matplotlib.figure import Figure
from matplotlib.backends.backend_agg import FigureCanvasAgg
from PyQt5.QtGui import QPixmap, QImage
from PyQt5.QtWidgets import QGraphicsScene


def simple_visualization(script_name, interval_id, data, border_coords, location_df, static_file_path):

    """Create a visualization figure that can be displayed in QGraphicsView.
    
    Args:
        script_name: Name of the script
        interval_id: Interval ID to visualize
        data: DataFrame containing object data
        border_coords: List of (lat, lon) tuples for border points
        location_df: DataFrame containing interval locations
        static_file_path: Path to static map points file
        
    Returns:
        A QGraphicsScene containing the visualization, or None if failed
    """
    fig = Figure(figsize=(10, 8), dpi=100)
    ax = fig.add_subplot(111)

    # Find matching interval
    match = location_df[
        (location_df['Script_Name'] == script_name) &
        (location_df['Interval_ID'] == interval_id)
    ]
    if match.empty:
        print(f"No matching interval found for script '{script_name}' and Interval_ID {interval_id}")
        return None

    interval_label = match['Interval'].iloc[0]

    # Get script data
    script_data = data[
        (data['Script_Name'] == script_name) & 
        (data['Interval'] == interval_label)
    ]

    if script_data.empty:
        print(f"No object data found for script '{script_name}' and interval '{interval_label}'")
        return None

    # Read static map points
    try:
        map_df = pd.read_excel(static_file_path)
        map_df.columns = map_df.columns.str.strip().str.lower()
        if not {'latitude', 'longitude', 'name'}.issubset(map_df.columns):
            print("Static map file must contain 'latitude', 'longitude', and 'name' columns.")
            return None
    except Exception as e:
        print(f"Failed to read static map points: {e}")
        return None

    # Plotting
    # 1. Plot border lines (underneath everything)
    if border_coords:
        border_lats, border_lons = zip(*border_coords)
        ax.plot(border_lats, border_lons, linestyle='--', color='blue', linewidth=2, alpha=0.7)
        ax.scatter(border_lats, border_lons, c='blue', marker='x', s=90)

    # 2. Plot static map lines
    for name, group in map_df.groupby('name'):
        lats = group['latitude'].tolist()
        lons = group['longitude'].tolist()
        if len(lats) > 1:
            ax.plot(lats, lons, linestyle='--', color='blue', linewidth=2)
        ax.scatter(lats, lons, c='blue', marker='x', s=90)

    # 3. Plot object positions (on top)
    close_points = script_data[script_data['Position'] == 'Close']
    not_close_points = script_data[script_data['Position'] == 'Not Close']

    if not close_points.empty:
        ax.scatter(close_points['Latitude'], close_points['Longitude'], 
                   c='red', label='Close Points', s=100, alpha=1, zorder=5)
    if not not_close_points.empty:
        ax.scatter(not_close_points['Latitude'], not_close_points['Longitude'], 
                   c='green', label='Not Close Points', s=100, alpha=1, zorder=5)

    ax.set_xlabel('Latitude')
    ax.set_ylabel('Longitude')
    ax.set_title(f'Object Positions for {script_name} (Interval ID: {interval_id})')
    ax.legend()
    ax.invert_xaxis()
    fig.tight_layout()

    # Convert matplotlib figure to QGraphicsScene
    canvas = FigureCanvasAgg(fig)
    canvas.draw()
    
    # Get the image as an RGBA buffer
    buf = canvas.buffer_rgba()
    width, height = canvas.get_width_height()
    
    # Create QImage from the buffer
    qimage = QImage(buf, width, height, QImage.Format_RGBA8888)
    pixmap = QPixmap.fromImage(qimage)
    
    # Create QGraphicsScene and add the pixmap
    scene = QGraphicsScene()
    scene.addPixmap(pixmap)
    
    return scene