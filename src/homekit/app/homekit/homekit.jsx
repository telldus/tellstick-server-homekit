define(
	['react', 'react-mdl'],
function(React, ReactMDL) {
	class HomekitConfiguration extends React.Component {
		render() {
			return (
				<div style={{position: 'relative'}}>
					<link rel="stylesheet" type="text/css" href="/homekit/stylesheet.css" />
					<img src="/homekit/code.png" />
					<div style={{
						position: 'absolute',
						left: '125px',
						top: '40px',
					}} className="homekit-code">{this.props.value}</div>
				</div>
			)
		}
	};
	return HomekitConfiguration;
});
