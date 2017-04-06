var gulp = require('gulp');
var babel = require("gulp-babel");
var requirejsOptimize = require('gulp-requirejs-optimize');

gulp.task('default', ['scripts'], function() {
});

gulp.task("babel", function () {
	return gulp.src(['src/homekit/app/**/*.jsx', 'src/homekit/app/**/*.js'])
		.pipe(babel({
			presets: ['es2015', 'stage-0', 'react']
		}))
		.pipe(gulp.dest('src/homekit/build'));
});

gulp.task('scripts', ['babel'], function () {
	return gulp.src('src/homekit/build/homekit/homekit.js')
		.pipe(requirejsOptimize({
			paths: {
				'react': 'empty:',
				'react-mdl': 'empty:',
				'react-redux': 'empty:',
				'dialog-polyfill': 'empty:',
				'telldus': 'empty:',
				'websocket': 'empty:',
			},
			baseUrl: 'src/homekit/build',
			name: 'homekit/homekit'
		}))
		.pipe(gulp.dest('src/homekit/htdocs'));
});

gulp.task('watch', ['default'], function() {
	gulp.watch(['src/homekit/app/**/*.jsx', 'src/homekit/app/**/*.js'], ['default']);
});
