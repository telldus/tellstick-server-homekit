define(
	['react', 'react-mdl'],
function(React, ReactMDL) {
	class HomekitConfiguration extends React.Component {
		render() {
			return (
				<div style={{position: 'relative'}}>
					<img src="/homekit/code.png" />
					<tt style={{
						position: 'absolute',
						left: '133px',
						top: '38px',
						fontSize: '30px',
						color: '#000'
					}}>{this.props.value}</tt>
				</div>
			)
		}
	};
	return HomekitConfiguration;
});
