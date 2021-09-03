-- [origin]

select
	ps_partkey,
	sum(ps_supplycost * ps_availqty) as value
from
	partsupp,
	supplier,
	nation
where
	ps_suppkey = s_suppkey
	and s_nationkey = n_nationkey
	and n_name = 'CANADA'
group by
	ps_partkey
having
		sum(ps_supplycost * ps_availqty) > (
			select
				sum(ps_supplycost * ps_availqty) * 0.0000010000
			from
				partsupp,
				supplier,
				nation
			where
				ps_suppkey = s_suppkey
				and s_nationkey = n_nationkey
				and n_name = 'CANADA'
		)
order by
	value desc 
  

-- [default] change join type + decorrelate manually


select
	ps_partkey, 
	part_value
from (
	select
		ps_partkey,
		part_value,
		total_value
	from
		(
	select
		ps_partkey,
		sum(ps_supplycost * ps_availqty) as part_value
	from
		partsupp
		left join supplier on ps_suppkey = s_suppkey
		left join nation on s_nationkey = n_nationkey
	where
		n_name = 'CANADA'
	group by ps_partkey
), (
	select
		sum(part_value) as total_value
	from
		(
	select
		ps_partkey,
		sum(ps_supplycost * ps_availqty) as part_value
	from
		partsupp
		left join supplier on ps_suppkey = s_suppkey
		left join nation on s_nationkey = n_nationkey
	where
		n_name = 'CANADA'
	group by ps_partkey
)
))

where
	part_value > total_value * 0.0000010000
order by
	part_value desc

